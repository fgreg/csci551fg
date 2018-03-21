# Copyright 2018, Frank Greguska, All rights reserved.

"""
Functions in this file:
    main
    parse_config


This module parses the configuration file, sets up logging, initializes the UDP
socket, and then forks to run the proxy and the router.
"""
import ipaddress
import logging.config
import os
import sys
from collections import namedtuple

import pkg_resources

import csci551fg.proxy
import csci551fg.router

# Global vars used to keep track of configuration
num_routers = 0
stage = 1
minitor_hops = 1

# External interfaces available for assignment to routers
INTERFACES = [
    (ipaddress.IPv4Address('192.168.201.2'), 'eth1'),
    (ipaddress.IPv4Address('192.168.202.2'), 'eth2'),
    (ipaddress.IPv4Address('192.168.203.2'), 'eth3'),
    (ipaddress.IPv4Address('192.168.204.2'), 'eth4'),
    (ipaddress.IPv4Address('192.168.205.2'), 'eth5'),
    (ipaddress.IPv4Address('192.168.206.2'), 'eth6')
]

# The address space of the routers
ROUTER_SUBNET = ipaddress.IPv4Network('10.5.51.0/24')

# Buffer sizes for reading from the socket and tunnel
UDP_BUFFER_SIZE = 2048
TUNNEL_BUFFER_SIZE = 2048

# Setup some basic logging for help with debugging
logging.config.fileConfig(pkg_resources.resource_filename('csci551fg', 'logging.ini'), disable_existing_loggers=False)
log = logging.getLogger('csci551fg.driver')

RouterConfig = namedtuple('RouterConfig', [
    'proxy_address', 'stage', 'num_routers',
    'router_index', 'buffer_size', 'ip_address',
    'interface_name', 'pid', 'router_subnet'
])

def main():
    """
    Opens a port, forks routers and starts the proxy.
    """
    conf_file = sys.argv[1]
    parse_config(conf_file)

    log.debug("num_routers: %d, stage: %d, minitor_hops: %s" % (num_routers, stage, minitor_hops if minitor_hops else "N/A"))

    # Setup log for proxy then open the UDP port for routers
    csci551fg.proxy.setup_log(stage)
    proxy_address = csci551fg.proxy.bind_router_socket(stage=stage, num_hops=minitor_hops)

    routers = []
    child = False
    router_index = 0
    for router_index in range(0, num_routers):
        child_pid = os.fork()
        if child_pid == 0:
            child = True
            break
        else:
            log.debug("forked pid %d" % child_pid)
            routers.append(child_pid)

    if not child:
        csci551fg.proxy.proxy(routers=routers, stage=stage)
    else:
        interface = INTERFACES[router_index]
        router_conf = RouterConfig(proxy_address=proxy_address, stage=stage,
            num_routers=num_routers, router_index=router_index,
            buffer_size=UDP_BUFFER_SIZE, ip_address=interface[0], interface_name=interface[1],
            pid=os.getpid(), router_subnet=ROUTER_SUBNET)
        csci551fg.router.setup_log(stage, router_conf.router_index)
        csci551fg.router.router(router_conf)

    log.debug("pid %d exit" % os.getpid())


def parse_config(conf_file):
    """
    Parses the configuration file given by conf_file to extract the stage
     number and number of routers.
    """
    config = []
    with open(conf_file, mode='r') as conf:
        for line in conf.readlines():
            if str(line).startswith('#'):
                continue
            else:
                config.append(line)

    global stage
    stage = next(iter([l for l in config if "stage" in l]), None)
    if stage:
        stage = int(stage.split(' ')[-1])
    global num_routers
    num_routers = next(iter([l for l in config if "num_routers" in l]), None)
    if num_routers:
        num_routers = int(num_routers.split(' ')[-1])
    global minitor_hops
    minitor_hops = next(iter([l for l in config if "minitor_hops" in l]), None)
    if minitor_hops:
        minitor_hops = int(minitor_hops.split(' ')[-1])

# Called when module is run
if __name__ == '__main__':
    main()
