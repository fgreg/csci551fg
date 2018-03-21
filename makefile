# Copyright 2018, Frank Greguska, All rights reserved.

default:
    sudo dnf install -y redhat-rpm-config
    sudo dnf install -y python3-devel
    sudo setcap cap_net_raw+ep /usr/bin/python3.6
    pip3 install --user pycrypto


	python3 setup.py install --user
	touch proja
	chmod +x proja
	@echo "#!/bin/bash" > proja
	@echo "set -e" >> proja
	@echo "python3 -m csci551fg.driver \"\$$@\"" >> proja

.PHONY : clean
clean :
        -rm default $(objects)