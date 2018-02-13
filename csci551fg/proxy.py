import logging
import os
import socket
import selectors
import ipaddress
import csci551fg.tunnel
import csci551fg.icmp

from csci551fg.driver import UDP_BUFFER_SIZE, TUNNEL_BUFFER_SIZE

proxy_logger = logging.getLogger('csci551fg.proxy')
proxy_selector = selectors.DefaultSelector()
routers = []

def setup_log(stage):
    proxy_handler = logging.FileHandler(os.path.join(os.curdir, "stage%d.proxy.out" % stage), mode='w')
    proxy_handler.setFormatter(logging.Formatter("%(message)s"))
    proxy_handler.setLevel(logging.INFO)

    proxy_logger.addHandler(proxy_handler)
    proxy_logger.setLevel(logging.DEBUG)

def bind_router_socket():
    my_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.bind((socket.gethostbyname(socket.gethostname()), 0))

    proxy_selector.register(my_socket, selectors.EVENT_READ, read_router)

    return my_socket.getsockname()

def read_router(connection, mask):
    data, address = connection.recvfrom(UDP_BUFFER_SIZE)
    proxy_logger.debug("Proxy received data from router @ %s" % str(address))
    received_pid = int.from_bytes(data, byteorder='big')
    proxy_logger.info("router: %d, pid: %d, port: %d" % (routers.index(received_pid), received_pid, address[1]))

def read_tunnel(tunnel, mask):
    data = tunnel.read(TUNNEL_BUFFER_SIZE)
    proxy_logger.debug("Proxy received data from tunnel %s" % str(data))

    echo_message = csci551fg.icmp.ICMPEcho(data)
    proxy_logger.info("ICMP from tunnel, src: %s, dst: %s, type: %s", echo_message.source_ipv4, echo_message.destination_ipv4, echo_message.icmp_type)

def proxy(**kwargs):
    proxy_logger.debug("starting proxy %s" % kwargs)

    if kwargs['stage'] == 2:
        my_tunnel = csci551fg.tunnel.tun_alloc("tun1", [csci551fg.tunnel.IFF_TUN, csci551fg.tunnel.IFF_NO_PI])
        proxy_selector.register(my_tunnel, selectors.EVENT_READ, read_tunnel)

    global routers
    routers = kwargs['routers']

    while True:
        events = proxy_selector.select()
        for key, mask in events:
            func = key.data
            func(key.fileobj, mask)
