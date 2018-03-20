a) No code was reused for this stage.

b) This stage is complete with the exception of logging the IP address of the previous hop from middle hop routers. I don't think this is possible and have addressed my concern to Lan. I have chosen instead to change the destination address to the IP address of the VM guest's ethernet interface when forwarding Relay Reply Data packets:
		"Hi Lan,

		I'm trying to understand this section of relay return data in stage 5:

		The public-facing and middle-hop routers will forward relay-return packets. Each hop,
		they will need to map the circuit ID backwards, and map the destination IP to the next
		hop in the circuit, working back to the proxy. Eventually this packet will arrive back at
		the proxy. Middle routers should log: relay reply packet, circuit incoming: 0xIDi, outgoing:
		0xIDo, src: S, incoming dst: Di, outgoing dst: Do.

		The routers are not aware of the external IP addresses mapped to other routers, as they communicate to one another via UDP. So I don't understand how we can "map the destination IP to the next hop in the circuit".

		I looked at your sample output and you are logging:
		relay reply packet, circuit incoming: 0x101, outgoing: 0x01, src: 128.30.2.155, incoming dst: 192.168.201.2, outgoing dest: 192.168.97.131

		but 192.168.97.131 is not an IP address of any of your routers. It seems like this is likely the IP address of your VM guest's ethernet interface.


		What should we log as outgoing dst for the middle hop routers?"

c) Mantitor extends circuits through partially built circuits instead of contacting the the current hop directly in order to maintain backwards anonymity. "Bob", the last hop, should not know who or where "Alice", the first hop, is.