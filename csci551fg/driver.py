import sys
import logging

from . import proxy
from . import router

num_routers = 0

def main():
    logging.basicConfig(format='%(message)s')
    logging.getLogger('proxy').addhan

    conf_file = sys.argv[1]
    parse_config(conf_file)

    print(num_routers)

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
