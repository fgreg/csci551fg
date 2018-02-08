import sys
import os
import pkg_resources
import logging
import logging.config

import csci551fg.proxy
import csci551fg.router

num_routers = 0
stage = 1

logging.config.fileConfig(pkg_resources.resource_filename('csci551fg', 'logging.ini'), disable_existing_loggers=False)
log = logging.getLogger('csci551fg.driver')


def main():
    conf_file = sys.argv[1]
    parse_config(conf_file)

    log.debug("num_routers: %d" % num_routers)

    csci551fg.proxy.setup_log(stage)
    udp_address = csci551fg.proxy.bind_socket()

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
        csci551fg.proxy.proxy(stage=stage, num_routers=num_routers, buffer_size=4, routers=routers)
    else:
        csci551fg.router.setup_log(stage, router_index)
        csci551fg.router.router(udp_address=udp_address, stage=stage, num_routers=num_routers, router_index=router_index, buffer_size=4)

    log.debug("pid %d exit" % os.getpid())


def parse_config(conf_file):
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


if __name__ == '__main__':
    main()
