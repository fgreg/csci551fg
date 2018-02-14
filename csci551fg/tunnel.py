"""
This module handles opening a connection to a tun/tap interface.

It has been created with the help of:

[1] https://ant.isi.edu/csci551_sp2018/sample_tunnel.c
[2] http://www.secdev.org/projects/tuntap_udp/files/tunproxy.py
[3] https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h
[4] https://github.com/spotify/linux/blob/master/include/linux/if.h
[5] http://backreference.org/2010/03/26/tuntap-interface-tutorial/


"""
import functools
import fcntl
import struct
import operator

# Constants from [3]
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# This magic hex number comes from linux/if_tun.h I was able to find the value
# on this system by writing a small c program that simply printed the value. This
# may be system depnedent though so this code is not portable.
TUNSETIFF = 0x400454ca

def tun_alloc(tunnel_name, flags):
    """
    Opens connection to the tunnel named by tunel_name using flags. Flags are or'ed together.
    """

    # The device is called the clone device, because it's used as a starting point for the creation of
    # any tun/tap virtual interface. [5]
    clone_device = "/dev/net/tun"

    # Open file decriptor to the clone device in bytes read/write mode with buffering disabled
    tunnel_file_descriptor = open(clone_device, mode="rb+", buffering=0)

    # Build the request for connecting the tunnel interface
    # 16sH is a 16 byte char[] followed by a short
    # 16 because that is the size of IFNAMSIZ (The name of the tunnel)
    interface_request = struct.pack("16sH", tunnel_name.encode(), functools.reduce(operator.ior, flags))

    # Set the name of the tunnel and flags. This essentially connects to the tunnel
    fcntl.ioctl(tunnel_file_descriptor, TUNSETIFF, interface_request)

    return tunnel_file_descriptor
