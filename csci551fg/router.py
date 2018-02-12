import logging
import os
import socket

router_logger = logging.getLogger('csci551fg.router')


def setup_log(stage, router_index):
    router_handler = logging.FileHandler(os.path.join(os.curdir, "stage%d.router%d.out" % (stage, router_index)), mode='w')
    router_handler.setFormatter(logging.Formatter("%(message)s"))
    router_handler.setLevel(logging.INFO)

    router_logger.addHandler(router_handler)
    router_logger.setLevel(logging.DEBUG)

def router(**kwargs):
    router_logger.debug("router args %s" % kwargs)
    router_logger.info("router: %d, pid: %d, port: %d" % (kwargs['router_index'], os.getpid(), kwargs['udp_address'][1]))
    router_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    router_sock.connect(kwargs['udp_address'])
    router_sock.sendall(os.getpid().to_bytes(kwargs['buffer_size'], byteorder='big'))

def icmp_echo_loop(router_sock, buffer_size):

    while True:
        data, address = router_sock.recvfrom(buffer_size)
