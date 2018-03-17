a) No code was reused for this stage.

b) This stage is complete.

c) I don't rewrite the source address in my proxy. I rewrite the source address in my router to match the IP address of that router. This is important because the response should be returned to the router in order to go back through the proxy and out of the tunnel. If the original address was used, the reply would simply go to the originating interface (eth0) instead of passing through my router and proxy.

d) The host OS modifies the outgoing packets and sets the source IP to the IP address of the host before sending it out the external interface.

