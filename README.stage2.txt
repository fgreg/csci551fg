


Give python3 cap_net_admin privileges so it can interact with the tunnel device.
sudo setcap cap_net_admin,cap_net_raw+eip /usr/bin/python3.6
