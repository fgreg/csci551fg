

sudo dnf install redhat-rpm-config
sudo dnf install python3-devel
pip3 install --user pycrypto

sudo setcap cap_net_raw+ep /usr/bin/python3.6