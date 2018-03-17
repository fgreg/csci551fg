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
import functools
import csci551fg.tunnel
import csci551fg.icmp

from csci551fg.driver import UDP_BUFFER_SIZE, TUNNEL_BUFFER_SIZE

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

def bind_router_socket(stage=None):
    my_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.bind((socket.gethostbyname(socket.gethostname()), 0))

    handler = functools.partial(handle_udp_socket, stage=stage)

    proxy_selector.register(my_socket, selectors.EVENT_READ | selectors.EVENT_WRITE, handler)

    proxy_logger.info("proxy port: %d" % my_socket.getsockname()[1])

    return my_socket.getsockname()

def handle_udp_socket(udp_socket, mask, stage=None):
    global routers
    if mask & selectors.EVENT_READ:
        data, address = udp_socket.recvfrom(UDP_BUFFER_SIZE)
        proxy_logger.debug("Proxy received data from router @ %s" % str(address))

        # Don't try to handle any ICMP packets before we get a hello from every router
        if any(router["address"] is None for router in routers):
            received_pid = int.from_bytes(data, byteorder='big')
            router = next(router for router in routers if router["pid"] == received_pid)
            proxy_logger.info("router: %d, pid: %d, port: %d" \
              % (router['index'], received_pid, address[1]))

            router["address"] = address
            proxy_logger.debug("updated routers %s" % routers)
        else:
            echo_message = csci551fg.icmp.ICMPEcho(data)
            proxy_logger.info("ICMP from port: %s, src: %s, dst: %s, type: %s",
              address[1], echo_message.source_ipv4,
              echo_message.destination_ipv4, echo_message.icmp_type)

            _echo_replies.append(echo_message)

    if mask & selectors.EVENT_WRITE:
        if all(router["address"] is not None for router in routers) and _echo_messages:
            message = _echo_messages.pop()
            router = routers[0]
            routers = routers[-1:] + routers[:-1]
            udp_socket.sendto(message.packet_data, router['address'])

def handle_tunnel(tunnel, mask):
    if mask & selectors.EVENT_READ:
        data = tunnel.read(TUNNEL_BUFFER_SIZE)
        proxy_logger.debug("Proxy received data from tunnel\n%s" % str(data))

        echo_message = csci551fg.icmp.ICMPEcho(data)
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
