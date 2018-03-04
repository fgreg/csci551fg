# Copyright 2018, Frank Greguska, All rights reserved.

"""
This module parses the configuration file, sets up logging, initializes the UDP
socket, and then forks to run the proxy and the router.
"""
import sys
import os
import pkg_resources
import logging
import logging.config
import ipaddress
from collections import namedtuple

import csci551fg.proxy
import csci551fg.router

# Global vars used to keep track of configuration
num_routers = 0
stage = 1

INTERFACES = [(ipaddress.IPv4Address('192.168.201.2'), 'eth1')]

# Buffer sizes for reading from the socket and tunnel
UDP_BUFFER_SIZE = 2048
TUNNEL_BUFFER_SIZE = 2048

# Setup some basic logging for help with debugging
logging.config.fileConfig(pkg_resources.resource_filename('csci551fg', 'logging.ini'), disable_existing_loggers=False)
log = logging.getLogger('csci551fg.driver')

RouterConfig = namedtuple('RouterConfig', [
    'udp_address', 'stage', 'num_routers',
    'router_index', 'buffer_size', 'ip_address',
    'interface_name', 'pid'
])

def main():
    """
    Opens a port, forks routers and starts the proxy.
    """
    conf_file = sys.argv[1]
    parse_config(conf_file)

    log.debug("num_routers: %d" % num_routers)

    # Setup log for proxy then open the UDP port for routers
    csci551fg.proxy.setup_log(stage)
    udp_address = csci551fg.proxy.bind_router_socket(stage=stage)

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
        inteface = INTERFACES.pop()
        router_conf = RouterConfig(udp_address=udp_address, stage=stage,
            num_routers=num_routers, router_index=router_index,
            buffer_size=UDP_BUFFER_SIZE, ip_address=inteface[0], interface_name=inteface[1],
            pid=os.getpid())
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
    stage = int(config[0].split(' ')[-1])
    global num_routers
    num_routers = int(config[1].split(' ')[-1])

# Called when module is run
if __name__ == '__main__':
    main()
