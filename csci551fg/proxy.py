# Copyright 2018, Frank Greguska, All rights reserved.

"""
Functions in this file:
    setup_log
    bind_router_socket
    handle_udp_socket
    _route_message
    _build_circuit
    _extend_circuit
    _relay_data
    _handle_echo
    _handle_minitor
    handle_tunnel
    proxy

This module is responsible for handling the proxy. It logs to the appropriate files
and read/write to both the UDP socket and the Tunnel pipes. Messages are stored
in memory while they are waiting to be written to one of the pipes.
"""
import functools
import ipaddress
import logging
import os
import random
import selectors
import socket
import struct
from collections import namedtuple

import csci551fg.crypto
import csci551fg.ipfg
import csci551fg.tunnel
from csci551fg.driver import UDP_BUFFER_SIZE, TUNNEL_BUFFER_SIZE

Circuit = namedtuple('Circuit', ['circuit_id', 'source_ip', 'first_hop', 'hops', 'ext_acked', 'extending', 'diffie'])
FlowId = namedtuple('FlowId', ('source_ip', 'source_port', 'dest_ip', 'dest_port', 'protocol'))

flow_map = dict()

proxy_logger = logging.getLogger('csci551fg.proxy')
proxy_selector = selectors.DefaultSelector()
routers = []


def setup_log(stage):
    proxy_handler = logging.FileHandler(os.path.join(os.curdir, "stage%d.proxy.out" % stage), mode='w')
    proxy_handler.setFormatter(logging.Formatter("%(message)s"))
    proxy_handler.setLevel(logging.INFO)

    proxy_logger.addHandler(proxy_handler)
    proxy_logger.setLevel(logging.DEBUG)


def bind_router_socket(stage=None, num_hops=None):
    global my_socket
    my_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.bind((socket.gethostbyname(socket.gethostname()), 0))

    handler = functools.partial(handle_udp_socket, stage=stage, num_hops=num_hops)

    proxy_selector.register(my_socket, selectors.EVENT_READ, handler)

    proxy_logger.info("proxy port: %d" % my_socket.getsockname()[1])

    return my_socket.getsockname()


def handle_udp_socket(udp_socket, mask, stage=None, num_hops=None):
    global routers
    if mask & selectors.EVENT_READ:
        data, address = udp_socket.recvfrom(UDP_BUFFER_SIZE)
        proxy_logger.debug("Proxy received data from router @ %s" % str(address))

        # Don't try to handle any ICMP packets before we get a hello from every router
        if any(router["address"] is None for router in routers):
            received_pid, ipv4_address = struct.unpack("!2I", data)
            router = next(router for router in routers if router["pid"] == received_pid)
            router["address"] = address
            if stage >= 4:
                router["ipv4_address"] = ipaddress.IPv4Address(ipv4_address)

            if stage >= 5:
                proxy_logger.info("router: %d, pid: %d, port: %d, IP: %s"
                                  % (router['index'] + 1, received_pid, address[1], router["ipv4_address"]))
            else:
                proxy_logger.info("router: %d, pid: %d, port: %d"
                                  % (router['index'] + 1, received_pid, address[1]))

            proxy_logger.debug("updated routers %s" % routers)
        else:

            message = csci551fg.ipfg.IPv4Packet(data)
            (ip_proto,) = struct.unpack("!B", message.protocol)
            if ip_proto == socket.IPPROTO_ICMP:
                message_handler = _handle_echo
            elif ip_proto == csci551fg.ipfg.IPPROTO_MINITOR:
                proxy_logger.info("pkt from port: %s, length: %s, contents: 0x%s" % (
                    address[1], len(message.packet_data[20:]), message.packet_data[20:].hex()))
                message_handler = _handle_minitor
            else:
                raise Exception(
                    "Could not determine message type in router. IP Protocol: %s, Message: %s" % (ip_proto, message))

            message_handler(data, address)


def _udp_send(stage, data_message, num_hops):
    if all(router["address"] is not None for router in routers):
        if stage <= 4:
            router_address = _route_message(data_message)
        elif stage > 4:
            if data_message.get_protocol() == socket.IPPROTO_ICMP:
                flow_id = FlowId(data_message.source_ipv4, 0,
                                 data_message.destination_ipv4, 0,
                                 data_message.get_protocol())
            else:
                flow_id = FlowId(data_message.source_ipv4, data_message.get_source_port(),
                                 data_message.destination_ipv4, data_message.get_destination_port(),
                                 data_message.get_protocol())

            if flow_id not in flow_map:
                flow_map[flow_id] = _build_new_circuit(stage, num_hops, encrypted=stage > 5)

            the_circuit = flow_map[flow_id]

            # Now send data
            (data_message, router_address) = _relay_data(the_circuit, data_message, stage, num_hops,
                                                         encrypted=stage > 5)

        proxy_logger.debug("Proxy sending message {} to {}".format(data_message, router_address))
        my_socket.sendto(data_message.packet_data, router_address)


def _route_message(message):
    global routers
    destination = message.destination_ipv4
    try:
        target_router = next((r for r in routers if r["ipv4_address"] == destination),
                             routers[int(destination) % len(routers)])
    except KeyError:
        target_router = routers[0]
        routers = routers[-1:] + routers[:-1]

    return target_router['address']


def _build_new_circuit(stage, num_hops, encrypted=False):
    # Establish circuit
    hops = random.sample(routers, num_hops)
    if stage > 5:
        # Create keys for each hop
        for router in hops:
            router['key'] = csci551fg.crypto.new_key(router['index'] + 1)
    the_circuit = Circuit(len(flow_map) + 1, None, hops[0], hops, [False] * len(hops), False, False)
    proxy_logger.debug("new circuit %s" % (the_circuit,))

    for hop_idx in range(0, len(the_circuit.hops)):
        router_num = the_circuit.hops[hop_idx]['index'] + 1
        proxy_logger.info("hop: %d, router: %s" % (hop_idx + 1, router_num))
        try:
            next_hop = the_circuit.hops[hop_idx + 1]
        except IndexError:
            next_hop = {'address': (None, csci551fg.ipfg.LAST_HOP)}

        if encrypted:
            key = the_circuit.hops[hop_idx]['key']
            proxy_logger.info("new-fake-diffie-hellman, router index: {}, circuit outgoing: {}, key: 0x{}".format(
                router_num, hex(the_circuit.circuit_id), key.hex()
            ))
            keys = [h['key'] for h in reversed(the_circuit.hops[:hop_idx])]
            message = csci551fg.ipfg.FakeDiffieHellman(bytes(39)) \
                .set_circuit_id(the_circuit.circuit_id) \
                .set_session_key(csci551fg.crypto.onion_encrypt(keys, key))

            my_socket.sendto(message.packet_data, the_circuit.first_hop['address'])

            # Send encrypted circuit extend
            keys = [h['key'] for h in reversed(the_circuit.hops[:hop_idx + 1])]
            message = csci551fg.ipfg.EncryptedCircuitExtend(bytes(25)) \
                .set_circuit_id(the_circuit.circuit_id) \
                .set_next_hop(csci551fg.crypto.onion_encrypt(keys, struct.pack("!H", next_hop['address'][1])),
                              packed=True)
        else:
            # Not building encrypted circuit, use regular circuit extend
            message = csci551fg.ipfg.CircuitExtend(bytes(25)) \
                .set_circuit_id(the_circuit.circuit_id) \
                .set_next_hop(next_hop['address'][1])

        my_socket.sendto(message.packet_data, the_circuit.first_hop['address'])
        data, address = my_socket.recvfrom(UDP_BUFFER_SIZE)

        ext_acks = the_circuit.ext_acked
        ext_acks[ext_acks.index(False)] = True
        the_circuit = Circuit(the_circuit.circuit_id, the_circuit.source_ip, the_circuit.first_hop, the_circuit.hops,
                              ext_acks, False, False)
        proxy_logger.debug("extend acked. %s" % (the_circuit,))
        proxy_logger.info("incoming extend-done circuit, incoming: %s from port: %d" % (
            hex(csci551fg.ipfg.MCMPacket(data).get_circuit_id()), address[1]))

    return the_circuit


def _relay_data(circuit, message, stage, num_hops, encrypted=False):

    if not encrypted:
        mcm_rd = csci551fg.ipfg.RelayData(bytes(23))
        mcm_rd = mcm_rd.set_circuit_id(circuit.circuit_id)
        message = mcm_rd.set_contents(message.packet_data)
        router_address = circuit.first_hop['address']
        proxy_logger.debug("relaying packet {} to {}".format(message, router_address))
    else:
        keys = [h['key'] for h in reversed(circuit.hops)]
        mcm_red = csci551fg.ipfg.RelayEncryptedData(bytes(23)) \
            .set_circuit_id(circuit.circuit_id) \
            .set_source(ipaddress.IPv4Address('0.0.0.0')) \
            .encrypt_contents(keys, message.set_source(ipaddress.IPv4Address('0.0.0.0')).packet_data)
        router_address = circuit.first_hop['address']

        message = mcm_red
        proxy_logger.debug("relaying encrypted packet {} to {}".format(message, router_address))

    return message, router_address


def _handle_echo(data, address):
    echo_message = csci551fg.ipfg.ICMPEcho(data)
    proxy_logger.info("ICMP from port: %s, src: %s, dst: %s, type: %s",
                      address[1], echo_message.source_ipv4,
                      echo_message.destination_ipv4, echo_message.icmp_type[0])

    tunnel_write(echo_message)


def _handle_minitor(data, address):
    mcm_message = csci551fg.ipfg.MCMPacket(data)
    mcm_type = mcm_message.get_message_type()
    id_i = mcm_message.get_circuit_id()
    flow_id, the_circuit = next(iter([(f, c) for f, c in flow_map.items() if c.circuit_id == id_i]))
    if mcm_type == csci551fg.ipfg.MCM_RRD:
        mcm_rrd = csci551fg.ipfg.RelayReturnData(data)
        i_packet = csci551fg.ipfg.IPv4Packet(mcm_rrd.contents)
        proxy_logger.info("incoming packet, circuit incoming: {}, src: {}, dst: {}".format(
            hex(id_i), i_packet.source_ipv4, i_packet.destination_ipv4
        ))
        tunnel_write(i_packet)
    elif mcm_type == csci551fg.ipfg.MCM_RRED:
        mcm_rred = csci551fg.ipfg.RelayReturnEncryptedData(data)

        contents = mcm_rred.contents
        for key in [h['key'] for h in the_circuit.hops]:
            contents = csci551fg.crypto.onion_decrypt(key, contents)
        i_packet = csci551fg.ipfg.IPv4Packet(contents)

        ip_proto = i_packet.get_protocol()
        if ip_proto == socket.IPPROTO_ICMP:
            proxy_logger.info("incoming packet, circuit incoming: {}, src: {}, dst: {}".format(
                hex(id_i), i_packet.source_ipv4, i_packet.destination_ipv4
            ))
            i_packet = csci551fg.ipfg.ICMPEcho(i_packet.packet_data).set_destination(flow_id.source_ip)
        elif ip_proto == socket.IPPROTO_TCP:
            tcp_packet = csci551fg.ipfg.TCPPacket(i_packet.packet_data).set_destination(flow_id.source_ip)
            proxy_logger.info("incoming TCP packet, circuit incoming: {}, src IP/port: {}:{}, "
                              "dst IP/port: {}:{}, seqno: {}, ackno: {}".format(
                hex(id_i), tcp_packet.source_ipv4, tcp_packet.get_source_port(),
                tcp_packet.destination_ipv4, tcp_packet.get_destination_port(), tcp_packet.get_sequence_no(),
                tcp_packet.get_ack_no()
            ))
            proxy_logger.debug("incoming TCP packet {}".format(tcp_packet))
            i_packet = csci551fg.ipfg.TCPPacket(i_packet.packet_data).set_destination(flow_id.source_ip)
        else:
            proxy_logger.debug("Unknown protocol for data returned {}. data {} ".format(ip_proto, i_packet))
            return
        tunnel_write(i_packet)
    else:
        raise Exception("Unkown MCM message. Type %s, Message %s" % (hex(mcm_type), mcm_message))


def tunnel_write(ipv4_packet):
    num_bytes = my_tunnel.write(ipv4_packet.packet_data)
    proxy_logger.debug("wrote %d bytes to tunnel" % num_bytes)


def handle_tunnel(tunnel, mask, stage=None, num_hops=None):
    if mask & selectors.EVENT_READ:
        data = tunnel.read(TUNNEL_BUFFER_SIZE)

        message = csci551fg.ipfg.IPv4Packet(data)
        (ip_proto,) = struct.unpack("!B", message.protocol)

        if message.source_ipv4 == ipaddress.IPv4Address('0.0.0.0'):
            proxy_logger.debug("Dropped 0.0.0.0")
            return

        if ip_proto == socket.IPPROTO_ICMP:
            message = csci551fg.ipfg.ICMPEcho(data)
            proxy_logger.info("ICMP from tunnel, src: %s, dst: %s, type: %s", message.source_ipv4,
                              message.destination_ipv4, struct.unpack("!B", message.icmp_type)[0])
        elif ip_proto == socket.IPPROTO_TCP:
            message = csci551fg.ipfg.TCPPacket(data)
            proxy_logger.info("TCP from tunnel, src IP/port: {}:{}, dst IP/port: {}:{}, seqno: {}, ackno {}".format(
                message.source_ipv4, message.get_source_port(), message.destination_ipv4,
                message.get_destination_port(), message.get_sequence_no(), message.get_ack_no()))
        else:
            raise Exception(
                "Could not determine message type in proxy. IP Protocol: %s, Message: %s" % (ip_proto, message))

        proxy_logger.debug("Proxy received data from tunnel {}".format(message))

        _udp_send(stage, message, num_hops)


def proxy(**kwargs):
    proxy_logger.debug("starting proxy %s" % kwargs)

    if kwargs['stage'] >= 2:
        global my_tunnel
        my_tunnel = csci551fg.tunnel.tun_alloc("tun1", [csci551fg.tunnel.IFF_TUN, csci551fg.tunnel.IFF_NO_PI])
        tunnel_handler = functools.partial(handle_tunnel, stage=kwargs['stage'], num_hops=kwargs['num_hops'])
        proxy_selector.register(my_tunnel, selectors.EVENT_READ, tunnel_handler)

    global routers
    routers = [{"index": i, "pid": r, "address": None} for i, r in enumerate(kwargs['routers'])]
    proxy_logger.debug("assigning routers %s" % routers)

    while True:
        events = proxy_selector.select()
        for key, mask in events:
            func = key.data
            func(key.fileobj, mask)
