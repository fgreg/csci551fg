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

router_logger = logging.getLogger('csci551fg.router')

router_selector = selectors.DefaultSelector()

# Queue for messages waiting to be sent out the external interfaces
_outgoing_external = []


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
    proxy_connection.connect(router_conf.udp_address)
    proxy_connection.sendall(router_conf.pid.to_bytes(router_conf.buffer_size, byteorder="big"))
    router_logger.info("router: %d, pid: %d, port: %d" % (router_conf.router_index, router_conf.pid, proxy_connection.getsockname()[1]))
    proxy_handler = functools.partial(handle_proxy_connection, router_config=router_conf)

    router_selector.register(proxy_connection, selectors.EVENT_READ | selectors.EVENT_WRITE, proxy_handler)

    # Setup the connection to the external interface_name
    external_connection = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
    external_connection.bind((str(router_conf.ip_address), 0))
    router_logger.debug("router %d bound to %s" % (router_conf.router_index, external_connection.getsockname()))
    external_handler = functools.partial(handle_external_connection, router_config=router_conf)

    router_selector.register(external_connection, selectors.EVENT_READ | selectors.EVENT_WRITE, external_handler)

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

        if echo_message.destination_ipv4 == router_config.ip_address \
           or echo_message.destination_ipv4 in router_config.router_subnet:
            router_logger.info("ICMP from port: %s, src: %s, dst: %s, type: %s",
              address[1], echo_message.source_ipv4, echo_message.destination_ipv4,
              echo_message.icmp_type)

            reply = echo_message.reply()
            router_logger.debug("Router replying with data\n%s" % (reply.packet_data))

            proxy_connection.sendto(reply.packet_data, address)
        else:

            

            _outgoing_external.append(echo_message)

def handle_external_connection(external_connection, mask, router_config=None):
    pass
    # if mask & selectors.EVENT_READ:
    #     data, address = external_connection.recvfrom(router_config.buffer_size)
    #     echo_message = csci551fg.icmp.ICMPEcho(data)
    #     router_logger.info("ICMP from port: %s, src: %s, dst: %s, type: %s",
    #       address[1], echo_message.source_ipv4, echo_message.destination_ipv4,
    #       echo_message.icmp_type)
    #
    #     reply = echo_message.reply()
    #     router_logger.debug("Router replying with data\n%s" % (reply.packet_data))
    #
    #     external_connection.sendto(reply.packet_data, address)
