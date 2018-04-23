# Copyright 2018, Frank Greguska, All rights reserved.

"""
Functions in this file:
    setup_log
    router
    handle_udp_connection
    _handle_echo
    _handle_minitor
    _handle_circuit_extend
    _handle_circuit_extend_done
    _handle_relay_data
    _handle_relay_reply_data
    _handle_relay_reply_encrypted_data
    _handle_fake_diffie_hellman
    _handle_encrypted_circuit_extend
    handle_external_connection

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

CircuitEntry = namedtuple('CircuitEntry', ('id_i', 'id_o', 'prev_hop', 'next_hop', 'key'))

FlowId = namedtuple('FlowId', ('source_ip', 'source_port', 'dest_ip', 'dest_port', 'protocol'))

router_logger = None

router_selector = selectors.DefaultSelector()

# Queue for messages waiting to be sent out the external interfaces
_outgoing_external_icmp = []
_outgoing_external_tcp = []

# Queue for messages being written by the UDP socket
_outgoing_udp = []

# List of known circuits
_circuit_list = []

_flow_map = dict()


def setup_log(stage, router_index):
    router_handler = logging.FileHandler(os.path.join(os.curdir, "stage%d.router%d.out" % (stage, router_index + 1)),
                                         mode='w')
    router_handler.setFormatter(logging.Formatter("%(message)s"))
    router_handler.setLevel(logging.INFO)

    global router_logger
    router_logger = logging.getLogger('csci551fg.router.%d' % (router_index + 1))
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

    # Setup the connection to the external interface_name for ICMP
    external_icmp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
    external_icmp_socket.bind((str(router_conf.ip_address), 0))
    router_logger.debug("icmp router %d bound to %s" % (router_conf.router_index, external_icmp_socket.getsockname()))

    # Setup the connection to the external interface_name for TCP
    external_tcp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_TCP)
    external_tcp_socket.bind((str(router_conf.ip_address), 0))
    router_logger.debug("tcp router %d bound to %s" % (router_conf.router_index, external_tcp_socket.getsockname()))

    external_handler = functools.partial(handle_external_connection, router_config=router_conf)
    router_selector.register(external_icmp_socket, selectors.EVENT_READ | selectors.EVENT_WRITE, external_handler)
    router_selector.register(external_tcp_socket, selectors.EVENT_READ | selectors.EVENT_WRITE, external_handler)

    # Start the select loop
    while True:
        events = router_selector.select()
        for key, mask in events:
            func = key.data
            func(key.fileobj, mask)


def handle_udp_connection(udp_connection, mask, router_config=None):
    import time
    time.sleep(.1)
    if mask & selectors.EVENT_READ:
        data, address = udp_connection.recvfrom(router_config.buffer_size)
        router_logger.debug("UDP packet received {} bytes from {}.".format(len(data), address))

        message = csci551fg.ipfg.IPv4Packet(data)
        ip_proto = message.get_protocol()
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

            n_bytes = udp_connection.sendto(message.packet_data, address)
            router_logger.debug(
                "UDP packet {} bytes. Sent {} bytes to {}".format(len(message.packet_data[:]), n_bytes, address))
    else:
        raise Exception("Unknown event on UDP socket {}".format(mask))


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
        _outgoing_external_icmp.append(outgoing)


def _handle_minitor(data, address, router_config, udp_connection):
    mcm_message = csci551fg.ipfg.MCMPacket(data)
    (mcm_type,) = struct.unpack("!B", mcm_message.message_type)
    router_logger.debug("from {} message {}".format(address, mcm_message))
    if mcm_type == csci551fg.ipfg.MCM_CE:
        _handle_circuit_extend(data, address, router_config, udp_connection)
    elif mcm_type == csci551fg.ipfg.MCM_CED or mcm_type == csci551fg.ipfg.MCM_ECED:
        _handle_circuit_extend_done(data, address, router_config, udp_connection)
    elif mcm_type == csci551fg.ipfg.MCM_RD:
        _handle_relay_data(data, address, router_config, udp_connection)
    elif mcm_type == csci551fg.ipfg.MCM_RRD:
        _handle_relay_reply_data(data, address, router_config, udp_connection)
    elif mcm_type == csci551fg.ipfg.MCM_FDH:
        _handle_fake_diffie_hellman(data, address, router_config, udp_connection)
    elif mcm_type == csci551fg.ipfg.MCM_ECE:
        _handle_encrypted_circuit_extend(data, address, router_config, udp_connection)
    elif mcm_type == csci551fg.ipfg.MCM_RED:
        _handle_relay_data(data, address, router_config, udp_connection, encrypted=True)
    elif mcm_type == csci551fg.ipfg.MCM_RRED:
        _handle_relay_reply_encrypted_data(data, address, router_config, udp_connection)
    else:
        raise Exception("Unkown MCM message. Type {}, Message {}".format(hex(mcm_type), mcm_message))


def _handle_circuit_extend(data, address, router_config, udp_connection):
    mcm_ce = csci551fg.ipfg.CircuitExtend(data)
    router_logger.debug("from %s, circuit extend %s\n%s" % (address, mcm_ce, (_circuit_list,)))
    (id_i,) = struct.unpack("!H", mcm_ce.circuit_id)
    known_circuit = next(iter([c for c in _circuit_list if c.id_i == id_i]), None)
    if known_circuit:
        # Known circuit, forward on
        ce_forward = mcm_ce.forward(known_circuit.id_o)

        router_logger.info("forwarding extend circuit: incoming: %s, outgoing: %s at %s"
                           % (hex(known_circuit.id_i), hex(known_circuit.id_o), known_circuit.next_hop))

        _outgoing_udp.append((ce_forward, ('127.0.0.1', known_circuit.next_hop)))

    else:
        # New circuit
        id_o = (router_config.router_index + 1) * 256 + (len(_circuit_list) + 1)
        (next_hop,) = struct.unpack("!H", mcm_ce.next_hop)
        _circuit_list.append(CircuitEntry(id_i, id_o, address[1], next_hop, None))
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


def _handle_relay_data(data, address, router_config, udp_connection, encrypted=False):
    mcm_rd = csci551fg.ipfg.RelayData(data)
    (id_i,) = struct.unpack("!H", mcm_rd.circuit_id)
    known_circuit = next(iter([c for c in _circuit_list if c.id_i == id_i]), None)
    if known_circuit:
        if known_circuit.next_hop != csci551fg.ipfg.LAST_HOP:
            if not encrypted:
                i_packet = csci551fg.ipfg.IPv4Packet(mcm_rd.contents)
                router_logger.info(
                    "relay packet, circuit incoming: {}, outgoing: {}, incoming src: {}, outgoing src: {}, dst:{}".format(
                        hex(id_i), hex(known_circuit.id_o), i_packet.source_ipv4, router_config.ip_address,
                        known_circuit.next_hop)
                )
                forward_data = mcm_rd.forward(router_config.ip_address, known_circuit.id_o)
                _outgoing_udp.append((forward_data, ('127.0.0.1', known_circuit.next_hop)))
            else:
                mcm_red = csci551fg.ipfg.RelayEncryptedData(mcm_rd.packet_data)
                mcm_red = mcm_red.set_contents(mcm_red.decrypt_contents(known_circuit.key)) \
                    .forward(None, known_circuit.id_o)

                _outgoing_udp.append((mcm_red, ('127.0.0.1', known_circuit.next_hop)))
                router_logger.info(
                    "relay encrypted packet, circuit incoming: {}, outgoing: {}".format(
                        hex(id_i), hex(known_circuit.id_o))
                )
        else:
            # Send external
            if encrypted:
                i_packet = csci551fg.ipfg.IPv4Packet(
                    csci551fg.ipfg.RelayEncryptedData(mcm_rd.packet_data).decrypt_contents(known_circuit.key))
            else:
                i_packet = csci551fg.ipfg.IPv4Packet(mcm_rd.contents)

            ip_proto = i_packet.get_protocol()
            if ip_proto == socket.IPPROTO_ICMP:
                icmp_packet = csci551fg.ipfg.ICMPEcho(i_packet.packet_data)
                flow_id = FlowId(icmp_packet.source_ipv4, 0, icmp_packet.destination_ipv4, 0, ip_proto)
                router_logger.debug("Saving flow id {}:{}".format(flow_id, known_circuit))
                _flow_map[flow_id] = known_circuit
                router_logger.info(
                    "outgoing packet, circuit incoming: {}, incoming src: {}, outgoing src: {}, dst: {}".format(
                        hex(id_i), i_packet.source_ipv4, router_config.ip_address, i_packet.destination_ipv4
                    ))
                _handle_echo(i_packet.packet_data, address, router_config, udp_connection)
            elif ip_proto == socket.IPPROTO_TCP:
                tcp_packet = csci551fg.ipfg.TCPPacket(i_packet.packet_data)

                incoming_source_ip = tcp_packet.source_ipv4
                tcp_packet = tcp_packet.set_source(router_config.ip_address)
                flow_id = FlowId(tcp_packet.source_ipv4, tcp_packet.get_source_port(), tcp_packet.destination_ipv4,
                                 tcp_packet.get_destination_port(), ip_proto)
                router_logger.debug("Saving flow id {}:{}".format(flow_id, known_circuit))
                _flow_map[flow_id] = known_circuit

                router_logger.info(
                    "outgoing TCP packet, circuit incoming: {}, incoming src IP/port: {}:{}, "
                    "outgoing src IP/port: {}:{}, dst IP/port: {}:{}, seqno: {}, ackno: {}".format(
                        hex(id_i), incoming_source_ip, tcp_packet.get_source_port(), tcp_packet.source_ipv4,
                        tcp_packet.get_source_port(), tcp_packet.destination_ipv4, tcp_packet.get_destination_port(),
                        tcp_packet.get_sequence_no(), tcp_packet.get_ack_no()
                    ))

                _outgoing_external_tcp.append(tcp_packet)
            else:

                raise Exception("Unknown protocol {}. Packet {}. contents: 0x{}".format(ip_proto, i_packet,
                                                                                        i_packet.packet_data.hex()))
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
    else:
        known_circuit = next(iter([c for c in _circuit_list if c.id_i == id_i]), None)
        mcm_rrd = mcm_rrd.set_circuit_id(known_circuit.id_i)

    i_packet = csci551fg.ipfg.IPv4Packet(mcm_rrd.contents)
    o_packet = i_packet.set_destination(ipaddress.IPv4Address('10.0.2.15'))
    mcm_rrd = mcm_rrd.set_contents(o_packet.packet_data)
    router_logger.info(
        "relay reply packet, circuit incoming: {}, outgoing: {}, src: {}, incoming dst: {}, outgoing dst: {}".format(
            hex(id_i), hex(known_circuit.id_i), i_packet.source_ipv4, i_packet.destination_ipv4,
            o_packet.destination_ipv4
        ))

    _outgoing_udp.append((mcm_rrd, ('127.0.0.1', known_circuit.prev_hop)))


def _handle_relay_reply_encrypted_data(data, address, router_config, udp_connection, encrypted=False):
    mcm_rred = csci551fg.ipfg.RelayReturnEncryptedData(data)
    (id_i,) = struct.unpack("!H", mcm_rred.circuit_id)
    known_circuit = next(iter([c for c in _circuit_list if c.id_o == id_i]), None)
    if known_circuit:
        # Reverse-Forward relay reply Messages
        mcm_rred = mcm_rred.set_circuit_id(known_circuit.id_i)
    else:
        known_circuit = next(iter([c for c in _circuit_list if c.id_i == id_i]), None)
        mcm_rred = mcm_rred.set_circuit_id(known_circuit.id_i)

    mcm_rred = mcm_rred.encrypt_contents([known_circuit.key], mcm_rred.contents)
    router_logger.info(
        "relay reply packet, circuit incoming: {}, outgoing: {}".format(
            hex(id_i), hex(known_circuit.id_i)
        ))

    _outgoing_udp.append((mcm_rred, ('127.0.0.1', known_circuit.prev_hop)))


def _handle_fake_diffie_hellman(data, address, router_config, udp_connection):
    mcm_fdh = csci551fg.ipfg.FakeDiffieHellman(data)
    (id_i,) = struct.unpack("!H", mcm_fdh.circuit_id)
    known_circuit = next(iter([c for c in _circuit_list if c.id_i == id_i]), None)
    if known_circuit:
        # Known circuit, decrypt key then forward
        router_logger.debug("known circuit {}".format(known_circuit))
        fdh_forward = mcm_fdh.forward(known_circuit.id_o, known_circuit.key)

        router_logger.info(
            "fake-diffie-hellman, forwarding, circuit incoming: {}, circuit outgoing: {}, key: 0x{}".format(
                hex(id_i), hex(known_circuit.id_o), fdh_forward.session_key.hex()
            ))

        _outgoing_udp.append((fdh_forward, ('127.0.0.1', known_circuit.next_hop)))

    else:
        # New circuit
        id_o = (router_config.router_index + 1) * 256 + (len(_circuit_list) + 1)
        (next_hop,) = (None,)
        _circuit_list.append(CircuitEntry(id_i, id_o, address[1], next_hop, mcm_fdh.session_key))
        router_logger.info("fake-diffie-hellman, new circuit incoming: {}, key: 0x{}".format(
            hex(id_i), mcm_fdh.session_key.hex()
        ))


def _handle_encrypted_circuit_extend(data, address, router_config, udp_connection):
    mcm_ece = csci551fg.ipfg.EncryptedCircuitExtend(data)
    (id_i,) = struct.unpack("!H", mcm_ece.circuit_id)
    known_circuit = next(iter([c for c in _circuit_list if c.id_i == id_i]), None)
    if known_circuit:
        if not known_circuit.next_hop:
            # This message is for us, fill in next hop and reply
            (next_hop,) = struct.unpack("!H", mcm_ece.decrypt_next_hop(known_circuit.key))
            router_logger.debug("decrypted next hop {}".format(next_hop))
            _circuit_list[_circuit_list.index(known_circuit)] = CircuitEntry(known_circuit.id_i, known_circuit.id_o,
                                                                             known_circuit.prev_hop, next_hop,
                                                                             known_circuit.key)
            router_logger.debug("circuit key 0x{} {}".format(_circuit_list[0].key.hex(), (_circuit_list,)))
            router_logger.info(
                "new encrypted extend circuit: incoming: %s, outgoing %s at %s" % (
                    hex(id_i), hex(known_circuit.id_o), next_hop))

            eced = mcm_ece.reply()

            _outgoing_udp.append((eced, address))
        else:
            # This message needs to be forwarded
            (next_hop,) = struct.unpack("!H", mcm_ece.decrypt_next_hop(known_circuit.key))
            ece_forward = mcm_ece.forward(known_circuit.id_o) \
                .set_next_hop(next_hop)
            router_logger.debug("decrypted next hop {}".format(next_hop))
            router_logger.info("forwarding encrypted extend circuit: incoming: %s, outgoing: %s at %s"
                               % (hex(known_circuit.id_i), hex(known_circuit.id_o), known_circuit.next_hop))

            _outgoing_udp.append((ece_forward, ('127.0.0.1', known_circuit.next_hop)))

    else:
        # Should never happen because diffie should always come first
        raise Exception("Unknown circuit when handling ECE")


def handle_external_connection(external_connection, mask, router_config=None):
    import time
    time.sleep(.1)
    if mask & selectors.EVENT_READ:
        data, address = external_connection.recvfrom(router_config.buffer_size)
        ip_packet = csci551fg.ipfg.IPv4Packet(data)

        # router_logger.debug("received message on external interface %s" % ip_packet)

        # Only process if it addressed to us
        if ip_packet.destination_ipv4 == router_config.ip_address:
            if router_config.stage <= 4:
                echo_message = csci551fg.ipfg.ICMPEcho(data)
                router_logger.info("ICMP from raw sock, src: %s, dst: %s, type: %s",
                                   ip_packet.source_ipv4, ip_packet.destination_ipv4, echo_message.icmp_type[0])

                incoming = ip_packet.set_destination(ipaddress.IPv4Address('10.0.2.15'))

                _outgoing_udp.append((incoming, router_config.proxy_address))
            else:
                if ip_packet.get_protocol() == socket.IPPROTO_ICMP:
                    flow_id = FlowId(ip_packet.destination_ipv4, 0, ip_packet.source_ipv4, 0, ip_packet.get_protocol())
                else:
                    tcp_packet = csci551fg.ipfg.TCPPacket(data)
                    flow_id = FlowId(ip_packet.destination_ipv4, tcp_packet.get_destination_port(),
                                     ip_packet.source_ipv4, tcp_packet.get_source_port(), ip_packet.get_protocol())

                try:
                    return_circuit = _flow_map[flow_id]
                except KeyError:
                    router_logger.debug("Unknown Flow id: {}".format(flow_id))
                    return

                router_logger.debug("Flow id: {}".format(flow_id))

                if router_config.stage == 5:
                    rrd = csci551fg.ipfg.RelayReturnData(bytes(23 + len(ip_packet.packet_data)))
                    rrd = rrd.set_contents(ip_packet.packet_data)
                else:
                    if ip_packet.get_protocol() == socket.IPPROTO_TCP:
                        contents = csci551fg.ipfg.TCPPacket(ip_packet.packet_data).set_destination(
                            ipaddress.IPv4Address('0.0.0.0')).packet_data
                    else:
                        contents = ip_packet.set_destination(ipaddress.IPv4Address('0.0.0.0')).packet_data
                    rrd = csci551fg.ipfg.RelayReturnEncryptedData(bytes(23 + len(contents)))
                    rrd = rrd.encrypt_contents([return_circuit.key], contents)
                rrd = rrd.set_circuit_id(return_circuit.id_i)
                router_logger.debug("rrd {} prev_hop {}".format(rrd, ('127.0.0.1', return_circuit.prev_hop)))

                if ip_packet.get_protocol() == socket.IPPROTO_ICMP:
                    router_logger.info("incoming packet, src: {}, dst: {}, outgoing circuit: {}".format(
                        ip_packet.source_ipv4, ip_packet.destination_ipv4, hex(return_circuit.id_i)
                    ))
                elif ip_packet.get_protocol() == socket.IPPROTO_TCP:
                    tcp_packet = csci551fg.ipfg.TCPPacket(data)
                    router_logger.debug("received message on external interface %s" % tcp_packet)
                    router_logger.info("incoming TCP packet, src IP/port: {}:{}, "
                                       "dst IP/port: {}:{}, seqno: {}, ackno: {}, outgoing circuit: {}".format(
                        tcp_packet.source_ipv4, tcp_packet.get_source_port(), tcp_packet.destination_ipv4,
                        tcp_packet.get_destination_port(), tcp_packet.get_sequence_no(), tcp_packet.get_ack_no(),
                        hex(return_circuit.id_i)
                    ))

                _outgoing_udp.append((rrd, ('127.0.0.1', return_circuit.prev_hop)))

    elif mask & selectors.EVENT_WRITE:
        if external_connection.proto == socket.IPPROTO_ICMP and _outgoing_external_icmp:
            outgoing = _outgoing_external_icmp.pop()
            router_logger.debug("Sending external ICMP %s" % outgoing)

            external_connection.sendmsg([outgoing.packet_data[20:]], [], 0, (str(outgoing.destination_ipv4), 0))
        elif external_connection.proto == socket.IPPROTO_TCP and _outgoing_external_tcp:
            outgoing = _outgoing_external_tcp.pop()
            router_logger.debug("Sending external TCP {}".format(outgoing))

            external_connection.sendto(outgoing.packet_data[20:], (str(outgoing.destination_ipv4),
                                                                   outgoing.get_destination_port()))
