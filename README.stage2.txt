a) There was no code directly reused but there was a lot of code referenced to implement my solution. Creating Python code to connect to the tunnel interface was the most challenging part and the following resources were all referenced in order to implement my solution:
https://ant.isi.edu/csci551_sp2018/sample_tunnel.c
http://www.secdev.org/projects/tuntap_udp/files/tunproxy.py
https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h
https://github.com/spotify/linux/blob/master/include/linux/if.h
http://backreference.org/2010/03/26/tuntap-interface-tutorial/

Furthermore, the following resources were used to implement details of the ICMP packet handling:
https://tools.ietf.org/html/rfc792
https://stackoverflow.com/questions/20247551/icmp-echo-checksum

The Python 3 reference materials for standard libraries was also referenced throughout the implementation. https://docs.python.org/3/library/

b) Stage 2 is complete and everything works.

c) This code is not portable. In particular, setting up the tunnel interface in python is not cross-platform compatible. In order to correctly initialize the tunnel, I need the value of the TUNSETIFF constant from linux/if_tun.h. This constant is calculated using sys/ioctl.h which is platform dependent. As far as I can tell there is no implementation of the c _IOW function available to Python, so I can not mimic the generation of the TUNSETIFF constant in Python.

Because of this, I needed to figure out the value of the TUNSETIFF constant generated for the platform running in the class VM. This value was 0x0400454ca and can be found in cscifs/tunnel.py. Because this constant value is specific to the platform running in the VM, it is not guaranteed that this code will be able to run on other architectures where this constant may be different.

Other than this platform dependent constant, the code should be portable to any other system that includes a python interpreter, with the exception of Windows, for the same reasons as stage 1.
