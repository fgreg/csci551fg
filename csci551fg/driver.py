import sys
import pkg_resources
import logging
import logging.config

import csci551fg.proxy
import csci551fg.router

num_routers = 0

logging.config.fileConfig(pkg_resources.resource_filename('csci551fg', 'logging.ini'))
log = logging.getLogger('csci551fg.driver')

def main():
    conf_file = sys.argv[1]
    parse_config(conf_file)

    log.info("num_routers: %d" % num_routers)

def parse_config(conf_file):
    config = []
    with open(conf_file, mode='r') as conf:
        for line in conf.readlines():
            if str(line).startswith('#'):
                continue
            else:
                config.append(line)

    global num_routers
    num_routers = int(config[1].split(' ')[-1])



if __name__ == '__main__':
    main()
