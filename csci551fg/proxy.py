import logging
import os
import socket

proxy_logger = logging.getLogger('csci551fg.proxy')
my_socket = None


def setup_log(stage):
    proxy_handler = logging.FileHandler(os.path.join(os.curdir, "stage%d.proxy.out" % stage), mode='w')
    proxy_handler.setFormatter(logging.Formatter("%(message)s"))
    proxy_handler.setLevel(logging.INFO)

    proxy_logger.addHandler(proxy_handler)
    proxy_logger.setLevel(logging.DEBUG)

def bind_socket():

    global my_socket
    my_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.bind((socket.gethostbyname(socket.gethostname()), 0))

    return my_socket.getsockname()


def proxy(**kwargs):
    proxy_logger.debug("starting proxy %s" % kwargs)

    while True:
        proxy_logger.debug("true")
        data = my_socket.recv(kwargs['buffer_size'])
        received_pid = int.from_bytes(data, byteorder='big')
        proxy_logger.info("router: %d, pid: %d, port: %d" % (kwargs['routers'].index(received_pid), received_pid, my_socket.getsockname()[1]))
