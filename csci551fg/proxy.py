# Copyright 2018, Frank Greguska, All rights reserved.

"""
This module is responsible for handling the proxy. It logs to the appropriate files
and read/write to both the UDP socket and the Tunnel pipes. Messages are stored
in memory while they are waiting to be written to one of the pipes.
"""
import logging
import sys
import os
import socket
import selectors
import ipaddress
import struct
import functools
import random
import csci551fg.tunnel
import csci551fg.ipfg

from csci551fg.driver import UDP_BUFFER_SIZE, TUNNEL_BUFFER_SIZE
from collections import namedtuple

Circuit = namedtuple('Circuit', ['circuit_id', 'first_hop', 'hops'])

the_circuit = None

proxy_logger = logging.getLogger('csci551fg.proxy')
proxy_selector = selectors.DefaultSelector()
routers = []

# Holding queue for messages waiting to go to the routers
_echo_messages = []
# Holding queue for messages waiting to go to the tunnel
_echo_replies = []

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
                    % (router['index']+1, received_pid, address[1], router["ipv4_address"]))
            else:
                proxy_logger.info("router: %d, pid: %d, port: %d" \
                    % (router['index']+1, received_pid, address[1]))

            proxy_logger.debug("updated routers %s" % routers)
        else:
            echo_message = csci551fg.ipfg.ICMPEcho(data)
            proxy_logger.info("ICMP from port: %s, src: %s, dst: %s, type: %s",
              address[1], echo_message.source_ipv4,
              echo_message.destination_ipv4, echo_message.icmp_type)

            _echo_replies.append(echo_message)

    if mask & selectors.EVENT_WRITE:
        if all(router["address"] is not None for router in routers) and _echo_messages:
            if stage <=4:
                message = _echo_messages.pop()
                router_address = _route_message(message)
            else:
                global the_circuit
                # Check if we've built the circuit yet
                if not the_circuit:
                    # Establish circuit
                    hops = random.sample(routers, num_hops)
                    the_circuit = Circuit(1, hops[0], hops)
                    proxy_logger.debug("new circuit %s" % (the_circuit,))

                # Check if the circuit is complete by seeing if we need to make any more hops
                if not the_circuit.hops:
                    # Circuit complete, Send data
                    message = _echo_messages.pop()
                else:
                    # Circuit incomplete, Extend circuit
                    message = csci551fg.ipfg.CircuitExtend(bytearray(25))
                    message = message.set_circuit_id(the_circuit.circuit_id)
                    message = message.set_next_hop(the_circuit.hops[0]['address'][1])
                    proxy_logger.info("hop: %d, router: %s" % (num_hops - len(the_circuit.hops) + 1, the_circuit.hops[0]['index']))

                router_address = the_circuit.first_hop['address']

            udp_socket.sendto(message.packet_data, router_address)

def _route_message(message):

    destination = message.destination_ipv4
    target_router = next((r for r in routers if r["ipv4_address"] == destination), routers[int(destination) % len(routers)])

    return target_router['address']

def handle_tunnel(tunnel, mask):
    if mask & selectors.EVENT_READ:
        data = tunnel.read(TUNNEL_BUFFER_SIZE)
        echo_message = csci551fg.ipfg.ICMPEcho(data)

        if(echo_message.source_ipv4 == ipaddress.IPv4Address('0.0.0.0')):
            proxy_logger.debug("Dropped 0.0.0.0")
            return

        proxy_logger.debug("Proxy received data from tunnel\n%s" % str(data))

        proxy_logger.info("ICMP from tunnel, src: %s, dst: %s, type: %s", echo_message.source_ipv4, echo_message.destination_ipv4, echo_message.icmp_type)
        _echo_messages.append(echo_message)

    if mask & selectors.EVENT_WRITE:
        if _echo_replies:
            reply = _echo_replies.pop()
            num_bytes= tunnel.write(reply.packet_data)
            proxy_logger.debug("wrote %d bytes to tunnel" % num_bytes)


def proxy(**kwargs):
    proxy_logger.debug("starting proxy %s" % kwargs)

    if kwargs['stage'] >= 2:
        my_tunnel = csci551fg.tunnel.tun_alloc("tun1", [csci551fg.tunnel.IFF_TUN, csci551fg.tunnel.IFF_NO_PI])
        proxy_selector.register(my_tunnel, selectors.EVENT_READ | selectors.EVENT_WRITE, handle_tunnel)

    global routers
    routers = [{"index": i, "pid":r, "address":None} for i, r in enumerate(kwargs['routers'])]
    proxy_logger.debug("assigning routers %s" % routers)

    while True:
        events = proxy_selector.select()
        for key, mask in events:
            func = key.data
            func(key.fileobj, mask)
