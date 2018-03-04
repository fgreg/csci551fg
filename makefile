# Copyright 2018, Frank Greguska, All rights reserved.

default:
	python3 setup.py install
	touch proja
	chmod +x proja
	@echo "#!/bin/bash" > proja
	@echo "set -e" >> proja
	@echo "python3 -m csci551fg.driver \"\$$@\"" >> proja
