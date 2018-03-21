a) No code was reused for this stage.

b) This stage is complete with the exception of logging the IP address of the previous hop from middle hop routers. I don't think this is possible and have addressed my concern with Lan. I have chosen instead to change the destination address to the IP address of the VM guest's ethernet interface when forwarding Relay Reply Data packets:

c) Mantitor extends circuits through partially built circuits instead of contacting the the current hop directly in order to maintain backwards anonymity. "Bob", the last hop, should not know who or where "Alice", the first hop, is.