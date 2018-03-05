# Copyright 2018, Frank Greguska, All rights reserved.

"""
This file is responsible for the router functions. It handles logging to the
correct files and responding to ICMP echo requests.
"""
import logging
import os
import socket
import sys
import csci551fg.icmp
import selectors
import functools
import ipaddress

router_logger = logging.getLogger('csci551fg.router')

router_selector = selectors.DefaultSelector()

# Queue for messages waiting to be sent out the external interfaces
_outgoing_external = []

# Queue for messages returning to the proxy
_incoming_proxy = []


def setup_log(stage, router_index):
    router_handler = logging.FileHandler(os.path.join(os.curdir, "stage%d.router%d.out" % (stage, router_index)), mode='w')
    router_handler.setFormatter(logging.Formatter("%(message)s"))
    router_handler.setLevel(logging.INFO)

    router_logger.addHandler(router_handler)
    router_logger.setLevel(logging.DEBUG)

def router(router_conf):

    router_logger.debug("router args %s" % router_conf._asdict())

    # Setup the connection to the proxy
    proxy_connection = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    proxy_connection.connect(router_conf.proxy_address)
    proxy_connection.sendall(router_conf.pid.to_bytes(router_conf.buffer_size, byteorder="big"))
    router_logger.info("router: %d, pid: %d, port: %d" % (router_conf.router_index, router_conf.pid, proxy_connection.getsockname()[1]))
    proxy_handler = functools.partial(handle_proxy_connection, router_config=router_conf)

    router_selector.register(proxy_connection, selectors.EVENT_READ | selectors.EVENT_WRITE, proxy_handler)

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

def handle_proxy_connection(proxy_connection, mask, router_config=None):

    if mask & selectors.EVENT_READ:
        data, address = proxy_connection.recvfrom(router_config.buffer_size)
        echo_message = csci551fg.icmp.ICMPEcho(data)
        router_logger.info("ICMP from port: %s, src: %s, dst: %s, type: %s",
          address[1], echo_message.source_ipv4, echo_message.destination_ipv4,
          echo_message.icmp_type)

        # If the echo is addressed to this router or to the router subnet, reply
        # directly back to the proxy
        if echo_message.destination_ipv4 == router_config.ip_address \
           or echo_message.destination_ipv4 in router_config.router_subnet:
            reply = echo_message.reply()
            router_logger.debug("Router replying with data\n%s" % (reply.packet_data))

            proxy_connection.sendto(reply.packet_data, address)
        # Otherwise, send it out the external interface
        else:
            outgoing = echo_message.set_source(router_config.ip_address)
            router_logger.debug("Incoming source %s, Outgoing source %s" % (echo_message.source_ipv4, outgoing.source_ipv4))
            _outgoing_external.append(outgoing)
    elif mask & selectors.EVENT_WRITE:
        if _incoming_proxy:
            echo_message = _incoming_proxy.pop()

            proxy_connection.sendto(echo_message.packet_data, router_config.proxy_address)

# def handle_external_socket(external_socket, mask):
#     if mask & selectors.EVENT_READ:
#         external_connection, external_address = external_socket.accept()
#         router_logger.debug("Accepted connection %s" % external_address)
#         external_handler = functools.partial(handle_external_connection, router_config=router_conf)
#
#         router_selector.register(external_connection, selectors.EVENT_READ, external_handler)
#     elif mask & selectors.EVENT_WRITE:
#         if _outgoing_external:
#             outgoing = _outgoing_external.pop()
#
#             router_logger.debug("Sending external %s" % outgoing)
#
#             external_socket.sendmsg([outgoing.packet_data], [], 0, (str(outgoing.destination_ipv4),1))


def handle_external_connection(external_connection, mask, router_config=None):
    if mask & selectors.EVENT_READ:
        data, address = external_connection.recvfrom(router_config.buffer_size)
        echo_message = csci551fg.icmp.ICMPEcho(data)

        router_logger.debug("received message on external interface %s" % echo_message)

        # Only process if it addressed to us
        if echo_message.destination_ipv4 == router_config.ip_address:
            router_logger.info("ICMP from raw sock, src: %s, dst: %s, type: %s",
                echo_message.source_ipv4, echo_message.destination_ipv4, echo_message.icmp_type)

            incoming = echo_message.set_destination(ipaddress.IPv4Address(router_config.proxy_address[0]))

            _incoming_proxy.append(incoming)

    elif mask & selectors.EVENT_WRITE:
        if _outgoing_external:
            outgoing = _outgoing_external.pop()

            router_logger.debug("Sending external %s" % outgoing)

            external_connection.sendmsg([outgoing.packet_data], [], 0, (str(outgoing.destination_ipv4),1))
