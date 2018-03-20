# Copyright 2018, Frank Greguska, All rights reserved.

"""
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

import csci551fg.ipfg
import csci551fg.tunnel
from csci551fg.driver import UDP_BUFFER_SIZE, TUNNEL_BUFFER_SIZE

Circuit = namedtuple('Circuit', ['circuit_id', 'first_hop', 'hops', 'extending'])

the_circuit = None

proxy_logger = logging.getLogger('csci551fg.proxy')
proxy_selector = selectors.DefaultSelector()
routers = []

# Holding queue for messages waiting to go to the routers
_echo_messages = []
# Holding queue for messages waiting to go to the tunnel
_echo_replies = []

_proxy_out_udp = []


def setup_log(stage):
    proxy_handler = logging.FileHandler(os.path.join(os.curdir, "stage%d.proxy.out" % stage), mode='w')
    proxy_handler.setFormatter(logging.Formatter("%(message)s"))
    proxy_handler.setLevel(logging.INFO)

    proxy_logger.addHandler(proxy_handler)
    proxy_logger.setLevel(logging.DEBUG)


def bind_router_socket(stage=None, num_hops=None):
    my_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.bind((socket.gethostbyname(socket.gethostname()), 0))

    handler = functools.partial(handle_udp_socket, stage=stage, num_hops=num_hops)

    proxy_selector.register(my_socket, selectors.EVENT_READ | selectors.EVENT_WRITE, handler)

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
                proxy_logger.info("router: %d, pid: %d, port: %d, IP: %s" \
                                  % (router['index'] + 1, received_pid, address[1], router["ipv4_address"]))
            else:
                proxy_logger.info("router: %d, pid: %d, port: %d" \
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

    if mask & selectors.EVENT_WRITE:
        global the_circuit
        if all(router["address"] is not None for router in routers):
            if stage <= 4 and _echo_messages:
                message = _echo_messages.pop()
                router_address = _route_message(message)
            elif not the_circuit:
                # Need to establish new circuit
                (message, router_address) = _build_circuit(stage, num_hops)
            elif the_circuit.hops and not the_circuit.extending:
                # Need to extend circuit
                (message, router_address) = _extend_circuit(stage, num_hops)
            elif not the_circuit.hops and _echo_messages:
                # Need to relay data
                message = _echo_messages.pop()
                mcm_rd = csci551fg.ipfg.RelayData(bytes(23))
                mcm_rd = mcm_rd.set_circuit_id(the_circuit.circuit_id)
                message = mcm_rd.set_contents(message.packet_data)
                router_address = the_circuit.first_hop['address']
                proxy_logger.debug("relaying packet {} to {}".format(mcm_rd, router_address))
            else:
                return

            _proxy_out_udp.append((message, router_address))

        if _proxy_out_udp:
            (message, router_address) = _proxy_out_udp.pop()
            udp_socket.sendto(message.packet_data, router_address)


def _route_message(message):
    destination = message.destination_ipv4
    target_router = next((r for r in routers if r["ipv4_address"] == destination),
                         routers[int(destination) % len(routers)])

    return target_router['address']


def _build_circuit(stage, num_hops):
    global the_circuit
    # Establish circuit
    hops = random.sample(routers, num_hops)
    the_circuit = Circuit(1, hops[0], hops, False)
    proxy_logger.debug("new circuit %s" % (the_circuit,))

    return _extend_circuit(stage, num_hops)


def _extend_circuit(stage, num_hops):
    global the_circuit
    # Circuit incomplete, Extend circuit
    the_circuit = Circuit(the_circuit.circuit_id, the_circuit.first_hop, the_circuit.hops, True)
    message = csci551fg.ipfg.CircuitExtend(bytearray(25))
    message = message.set_circuit_id(the_circuit.circuit_id)
    try:
        next_hop = the_circuit.hops[1]
        message = message.set_next_hop(next_hop['address'][1])
    except IndexError:
        next_hop = {'address': (None, csci551fg.ipfg.LAST_HOP)}
    message = message.set_next_hop(next_hop['address'][1])
    hop_num = num_hops - len(the_circuit.hops) + 1
    router_num = the_circuit.hops[0]['index'] + 1
    proxy_logger.info("hop: %d, router: %s" % (hop_num, router_num))

    router_address = the_circuit.first_hop['address']

    return message, router_address


def _handle_echo(data, address):
    echo_message = csci551fg.ipfg.ICMPEcho(data)
    proxy_logger.info("ICMP from port: %s, src: %s, dst: %s, type: %s",
                      address[1], echo_message.source_ipv4,
                      echo_message.destination_ipv4, echo_message.icmp_type)

    _echo_replies.append(echo_message)


def _handle_minitor(data, address):
    mcm_message = csci551fg.ipfg.MCMPacket(data)
    (mcm_type,) = struct.unpack("!B", mcm_message.message_type)
    if mcm_type == csci551fg.ipfg.MCM_CED:
        mcm_ced = csci551fg.ipfg.CircuitExtendDone(data)
        (id_i,) = struct.unpack("!H", mcm_ced.circuit_id)
        global the_circuit
        the_circuit = Circuit(the_circuit.circuit_id, the_circuit.first_hop, the_circuit.hops[1:], False)
        proxy_logger.debug("popped hop: %s" % (the_circuit,))
        proxy_logger.info("incoming extend-done circuit, incoming: %s from port: %d" % (hex(id_i), address[1]))
    else:
        raise Exception("Unkown MCM message. Type %s, Message %s" % (mcm_type, mcm_message))


def handle_tunnel(tunnel, mask):
    if mask & selectors.EVENT_READ:
        data = tunnel.read(TUNNEL_BUFFER_SIZE)
        echo_message = csci551fg.ipfg.ICMPEcho(data)

        if (echo_message.source_ipv4 == ipaddress.IPv4Address('0.0.0.0')):
            proxy_logger.debug("Dropped 0.0.0.0")
            return

        proxy_logger.debug("Proxy received data from tunnel\n%s" % str(data))

        proxy_logger.info("ICMP from tunnel, src: %s, dst: %s, type: %s", echo_message.source_ipv4,
                          echo_message.destination_ipv4, echo_message.icmp_type)
        _echo_messages.append(echo_message)

    if mask & selectors.EVENT_WRITE:
        if _echo_replies:
            reply = _echo_replies.pop()
            num_bytes = tunnel.write(reply.packet_data)
            proxy_logger.debug("wrote %d bytes to tunnel" % num_bytes)


def proxy(**kwargs):
    proxy_logger.debug("starting proxy %s" % kwargs)

    if kwargs['stage'] >= 2:
        my_tunnel = csci551fg.tunnel.tun_alloc("tun1", [csci551fg.tunnel.IFF_TUN, csci551fg.tunnel.IFF_NO_PI])
        proxy_selector.register(my_tunnel, selectors.EVENT_READ | selectors.EVENT_WRITE, handle_tunnel)

    global routers
    routers = [{"index": i, "pid": r, "address": None} for i, r in enumerate(kwargs['routers'])]
    proxy_logger.debug("assigning routers %s" % routers)

    while True:
        events = proxy_selector.select()
        for key, mask in events:
            func = key.data
            func(key.fileobj, mask)
