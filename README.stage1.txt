a) I did not use code from anywhere else in the completion of this project. For implementing sockets, I referenced the Python 3 documentation and examples which can be found here https://docs.python.org/3/library/socket.html.

b) Stage 1 is complete and everything works.

c) My code should work on Unix based operating systems but it will not work on Windows. Windows does not support the fork() command and therefore will not execute this code. Because I am using pure python, any Unix based OS with Python 3+ installed should be able to run this code. If the proxy and the router were run on different computers with different CPU architectures, the program should still function. This is because the Python interpreter effectively abstracts away the differences between the CPU architectures and allows the code to run.
