# Copyright 2018, Frank Greguska, All rights reserved.

default:
	sudo dnf install -y redhat-rpm-config
	sudo dnf install -y python3-devel
	sudo setcap cap_net_raw+ep /usr/bin/python3.6
	pip3 install --user pycrypto

	sudo pip3 install --user pycrypto

	python3 setup.py install --user
	sudo mkdir -p /usr/local/lib/python3.6/site-packages/
	sudo python3 setup.py install
	touch projb
	chmod +x projb
	@echo "#!/bin/bash" > projb
	@echo "set -e" >> projb
	@echo "python3 -m csci551fg.driver \"\$$@\"" >> projb

.PHONY : clean
clean :
	-rm default $(objects)