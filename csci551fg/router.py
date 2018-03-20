# Copyright 2018, Frank Greguska, All rights reserved.

"""
This file is responsible for the router functions. It handles logging to the
correct files and responding to ICMP echo requests.
"""
import functools
import ipaddress
import logging
import os
import selectors
import socket
import struct
from collections import namedtuple

import csci551fg.ipfg

CircuitEntry = namedtuple('CircuitEntry', ('id_i', 'id_o', 'prev_hop', 'prev_hop_ip', 'next_hop'))

router_logger = logging.getLogger('csci551fg.router')

router_selector = selectors.DefaultSelector()

# Queue for messages waiting to be sent out the external interfaces
_outgoing_external = []

# Queue for messages being written by the UDP socket
_outgoing_udp = []

# List of known circuits
_circuit_list = []


def setup_log(stage, router_index):
    router_handler = logging.FileHandler(os.path.join(os.curdir, "stage%d.router%d.out" % (stage, router_index + 1)),
                                         mode='w')
    router_handler.setFormatter(logging.Formatter("%(message)s"))
    router_handler.setLevel(logging.INFO)

    router_logger.addHandler(router_handler)
    router_logger.setLevel(logging.DEBUG)


def router(router_conf):
    router_logger.debug("router args %s" % router_conf._asdict())

    # Open a UDP Port
    udp_connection = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    udp_connection.bind((socket.gethostbyname(socket.gethostname()), 0))
    udp_connection.sendto(struct.pack("!2I", router_conf.pid, int(ipaddress.IPv4Address(router_conf.ip_address))),
                          router_conf.proxy_address)
    router_logger.info("router: %d, pid: %d, port: %d" % (
        router_conf.router_index + 1, router_conf.pid, udp_connection.getsockname()[1]))
    udp_handler = functools.partial(handle_udp_connection, router_config=router_conf)

    router_selector.register(udp_connection, selectors.EVENT_READ | selectors.EVENT_WRITE, udp_handler)

    # Setup the connection to the external interface_name
    external_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
    external_socket.bind((str(router_conf.ip_address), 0))
    router_logger.debug("router %d bound to %s" % (router_conf.router_index, external_socket.getsockname()))
    external_handler = functools.partial(handle_external_connection, router_config=router_conf)

    router_selector.register(external_socket, selectors.EVENT_READ | selectors.EVENT_WRITE, external_handler)

    # Start the select loop
    while True:
        events = router_selector.select()
        for key, mask in events:
            func = key.data
            func(key.fileobj, mask)


def handle_udp_connection(udp_connection, mask, router_config=None):
    if mask & selectors.EVENT_READ:
        data, address = udp_connection.recvfrom(router_config.buffer_size)

        message = csci551fg.ipfg.IPv4Packet(data)
        (ip_proto,) = struct.unpack("!B", message.protocol)
        if ip_proto == socket.IPPROTO_ICMP:
            message_handler = _handle_echo
        elif ip_proto == csci551fg.ipfg.IPPROTO_MINITOR:
            router_logger.info("pkt from port: %s, length: %s, contents: 0x%s" % (
                address[1], len(message.packet_data[20:]), message.packet_data[20:].hex()))
            message_handler = _handle_minitor
        else:
            raise Exception(
                "Could not determine message type in router. IP Protocol: %s, Message: %s" % (ip_proto, message))

        message_handler(data, address, router_config, udp_connection)

    elif mask & selectors.EVENT_WRITE:
        if _outgoing_udp:
            (message, address) = _outgoing_udp.pop()

            udp_connection.sendto(message.packet_data, address)


def _handle_echo(data, address, router_config, udp_connection):
    echo_message = csci551fg.ipfg.ICMPEcho(data)

    if router_config.stage <= 4:
        router_logger.info("ICMP from port: %s, src: %s, dst: %s, type: %s",
                           address[1], echo_message.source_ipv4, echo_message.destination_ipv4,
                           echo_message.icmp_type[0])

    # If the echo is addressed to this router or to the router subnet, reply
    # directly back to the proxy
    if echo_message.destination_ipv4 == router_config.ip_address \
            or echo_message.destination_ipv4 in router_config.router_subnet:
        reply = echo_message.reply()
        router_logger.debug("Router replying with data\n%s" % (reply.packet_data))

        udp_connection.sendto(reply.packet_data, address)
    # Otherwise, send it out the external interface
    else:
        outgoing = echo_message.set_source(router_config.ip_address)
        router_logger.debug("Incoming source %s, Outgoing source %s" % (echo_message.source_ipv4, outgoing.source_ipv4))
        _outgoing_external.append(outgoing)


def _handle_minitor(data, address, router_config, udp_connection):
    mcm_message = csci551fg.ipfg.MCMPacket(data)
    (mcm_type,) = struct.unpack("!B", mcm_message.message_type)
    if mcm_type == csci551fg.ipfg.MCM_CE:
        _handle_circuit_extend(data, address, router_config, udp_connection)
    elif mcm_type == csci551fg.ipfg.MCM_CED:
        _handle_circuit_extend_done(data, address, router_config, udp_connection)
    elif mcm_type == csci551fg.ipfg.MCM_RD:
        _handle_relay_data(data, address, router_config, udp_connection)
    elif mcm_type == csci551fg.ipfg.MCM_RRD:
        _handle_relay_reply_data(data, address, router_config, udp_connection)
    else:
        raise Exception("Unkown MCM message. Type %s, Message %s" % (mcm_type, mcm_message))


def _handle_circuit_extend(data, address, router_config, udp_connection):
    mcm_ce = csci551fg.ipfg.CircuitExtend(data)
    router_logger.debug("from %s, circuit extend %s" % (address, mcm_ce))
    (id_i,) = struct.unpack("!H", mcm_ce.circuit_id)
    known_circuit = next(iter([c for c in _circuit_list if c.id_i == id_i]), None)
    if known_circuit:
        # Known circuit, forward on
        ce_forward = mcm_ce.forward(known_circuit.next_hop)
        ce_forward = ce_forward.set_circuit_id(known_circuit.id_o)

        router_logger.info("forwarding extend circuit: incoming: %s, outgoing: %s at %s"
                           % (hex(known_circuit.id_i), hex(known_circuit.id_o), known_circuit.next_hop))

        _outgoing_udp.append((ce_forward, ('127.0.0.1', known_circuit.next_hop)))

    else:
        # New circuit
        id_o = (router_config.router_index + 1) * 256 + (len(_circuit_list) + 1)
        (next_hop,) = struct.unpack("!H", mcm_ce.next_hop)
        _circuit_list.append(CircuitEntry(id_i, id_o, address[1], router_config['ip_address'], next_hop))
        router_logger.info("new extend circuit: incoming: %s, outgoing %s at %s" % (hex(id_i), hex(id_o), next_hop))

        ced = mcm_ce.reply()

        _outgoing_udp.append((ced, address))


def _handle_circuit_extend_done(data, address, router_config, udp_connection):
    mcm_ced = csci551fg.ipfg.CircuitExtendDone(data)
    (id_i,) = struct.unpack("!H", mcm_ced.circuit_id)

    known_circuit = next(iter([c for c in _circuit_list if c.id_o == id_i]), None)
    if known_circuit:
        # Reverse-Forward circuit extend done Messages
        mcm_ced = mcm_ced.set_circuit_id(known_circuit.id_i)

        router_logger.info("forwarding extend-done circuit: incoming: %s, outgoing: %s at %s"
                           % (hex(id_i), hex(known_circuit.id_i), known_circuit.prev_hop))
    else:
        known_circuit = next(iter([c for c in _circuit_list if c.id_i == id_i]), None)

    _outgoing_udp.append((mcm_ced, ('127.0.0.1', known_circuit.prev_hop)))


def _handle_relay_data(data, address, router_config, udp_connection):
    mcm_rd = csci551fg.ipfg.RelayData(data)
    (id_i,) = struct.unpack("!H", mcm_rd.circuit_id)
    known_circuit = next(iter([c for c in _circuit_list if c.id_i == id_i]), None)
    if known_circuit:
        if known_circuit.next_hop != csci551fg.ipfg.LAST_HOP:
            forward_data = mcm_rd.forward(router_config.ip_address, known_circuit.id_o)
            _outgoing_udp.append((forward_data, ('127.0.0.1', known_circuit.next_hop)))
            i_packet = csci551fg.ipfg.IPv4Packet(mcm_rd.contents)
            router_logger.info(
                "relay packet, circuit incoming: {}, outgoing: {}, incoming src: {}, outgoing src: {}, dst:{}".format(
                    hex(id_i), hex(known_circuit.id_o), i_packet.source_ipv4, router_config.ip_address,
                    known_circuit.next_hop)
            )
        else:
            # Send external
            i_packet = csci551fg.ipfg.IPv4Packet(mcm_rd.contents)
            router_logger.info(
                "outgoing packet, circuit incoming: {}, incoming src: {}, outgoing src: {}, dst: {}".format(
                    hex(id_i), i_packet.source_ipv4, router_config.ip_address, i_packet.destination_ipv4
                ))
            _handle_echo(i_packet.packet_data, address, router_config, udp_connection)
    else:
        packet = csci551fg.ipfg.IPv4Packet(mcm_rd.contents)
        router_logger.info("unknown incoming circuit: %s, src: %s, dst: %s"
                           % (hex(id_i), packet.source_ipv4, packet.destination_ipv4))


def _handle_relay_reply_data(data, address, router_config, udp_connection):
    mcm_rrd = csci551fg.ipfg.RelayReturnData(data)
    (id_i,) = struct.unpack("!H", mcm_rrd.circuit_id)
    known_circuit = next(iter([c for c in _circuit_list if c.id_o == id_i]), None)
    if known_circuit:
        # Reverse-Forward relay reply Messages
        mcm_rrd = mcm_rrd.set_circuit_id(known_circuit.id_i)
        new_dest_ip = known_circuit.prev_ip
    else:
        known_circuit = next(iter([c for c in _circuit_list if c.id_i == id_i]), None)
        mcm_rrd = mcm_rrd.set_circuit_id(known_circuit.id_i)
        new_dest_ip = '10.0.2.15'

    i_packet = csci551fg.ipfg.IPv4Packet(mcm_rrd.contents)
    o_packet = i_packet.set_destination(ipaddress.IPv4Address(new_dest_ip))
    mcm_rrd = mcm_rrd.set_contents(o_packet.packet_data)
    router_logger.info(
        "relay reply packet, circuit incoming: {}, outgoing: {}, src: {}, incoming dst: {}, outgoing dst: {}".format(
            hex(id_i), hex(known_circuit.id_i), i_packet.source_ipv4, i_packet.destination_ipv4,
            new_dest_ip
        ))

    _outgoing_udp.append((mcm_rrd, ('127.0.0.1', known_circuit.prev_hop)))


def handle_external_connection(external_connection, mask, router_config=None):
    if mask & selectors.EVENT_READ:
        data, address = external_connection.recvfrom(router_config.buffer_size)
        echo_message = csci551fg.ipfg.ICMPEcho(data)

        router_logger.debug("received message on external interface %s" % echo_message)

        # Only process if it addressed to us
        if echo_message.destination_ipv4 == router_config.ip_address:
            if router_config.stage <= 4:
                router_logger.info("ICMP from raw sock, src: %s, dst: %s, type: %s",
                                   echo_message.source_ipv4, echo_message.destination_ipv4, echo_message.icmp_type[0])

                incoming = echo_message.set_destination(ipaddress.IPv4Address('10.0.2.15'))

                _outgoing_udp.append((incoming, router_config.proxy_address))
            else:
                return_circuit = _circuit_list[0]
                router_logger.info("incoming packet, src: {}, dst: {}, outgoing circuit: {}".format(
                    echo_message.source_ipv4, echo_message.destination_ipv4, hex(return_circuit.id_i)
                ))
                rrd = csci551fg.ipfg.RelayReturnData(bytes(23 + len(echo_message.packet_data)))
                rrd = rrd.set_contents(echo_message.packet_data)
                rrd = rrd.set_circuit_id(return_circuit.id_i)
                router_logger.debug("rrd {} prev_hop {}".format(rrd, ('127.0.0.1', return_circuit.prev_hop)))
                _outgoing_udp.append((rrd, ('127.0.0.1', return_circuit.prev_hop)))

    elif mask & selectors.EVENT_WRITE:
        if _outgoing_external:
            outgoing = _outgoing_external.pop()

            router_logger.debug("Sending external %s" % outgoing)

            external_connection.sendmsg([outgoing.packet_data[20:]], [], 0, (str(outgoing.destination_ipv4), 1))
