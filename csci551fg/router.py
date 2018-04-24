# Copyright 2018, Frank Greguska, All rights reserved.

"""
Functions in this file:

This file defines a Router class that is responsible for the router functions. It handles logging to the
correct files and responding to socket requests.
"""
import ipaddress
import logging
import os
import selectors
import socket
import struct
import threading
from collections import namedtuple

import csci551fg.ipfg

CircuitEntry = namedtuple('CircuitEntry', ('id_i', 'id_o', 'prev_hop', 'next_hop', 'key'))

FlowId = namedtuple('FlowId', ('source_ip', 'source_port', 'dest_ip', 'dest_port', 'protocol'))

# List of known circuits

RouterConfig = namedtuple('RouterConfig', [
    'proxy_address', 'stage', 'num_routers',
    'router_index', 'buffer_size', 'ip_address',
    'interface_name', 'pid', 'router_subnet'
])


class Router(object):

    def __init__(self, router_config):
        self.__dict__.update(**router_config._asdict())
        router_handler = logging.FileHandler(
            os.path.join(os.curdir, "stage%d.router%d.out" % (self.stage, self.router_index + 1)),
            mode='w')
        router_handler.setFormatter(logging.Formatter("%(message)s"))
        router_handler.setLevel(logging.INFO)

        router_logger = logging.getLogger('csci551fg.router.%d' % (self.router_index + 1))
        router_logger.addHandler(router_handler)
        router_logger.setLevel(logging.DEBUG)

        self.logger = router_logger

        self.selector = selectors.DefaultSelector()
        self.port = 0
        self.udp_connection = None
        self.external_icmp_socket = None
        self.external_tcp_socket = None

        self.circuit_list = []
        self.circuit_timer_map = dict()
        self.flow_map = dict()

    def __repr__(self):
        return "<Router {}>".format(self.__dict__)

    def start(self):
        self.udp_connection = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.udp_connection.setblocking(False)
        self.udp_connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size)
        self.udp_connection.bind((socket.gethostbyname(socket.gethostname()), self.port))
        self.port = self.udp_connection.getsockname()[1]
        self.udp_connection.sendto(struct.pack("!2I", self.pid, int(ipaddress.IPv4Address(self.ip_address))),
                                   self.proxy_address)
        if self.stage < 5:
            self.logger.info("router: {}, pid: {}, port: {}".format(self.router_index + 1, self.pid,
                                                                    self.port))
        else:
            self.logger.info("router: {}, pid: {}, port: {}, IP: {}".format(self.router_index + 1, self.pid,
                                                                            self.port,
                                                                            self.ip_address))
        self.selector.register(self.udp_connection, selectors.EVENT_READ, self.handle_udp_connection)

        # Setup the connection to the external interface_name for ICMP
        self.external_icmp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW,
                                                  proto=socket.IPPROTO_ICMP)
        self.external_icmp_socket.setblocking(False)
        self.external_icmp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size)
        self.external_icmp_socket.bind((str(self.ip_address), 0))
        self.logger.debug(
            "icmp router %d bound to %s" % (self.router_index, self.external_icmp_socket.getsockname()))

        # Setup the connection to the external interface_name for TCP
        self.external_tcp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_TCP)
        self.external_tcp_socket.setblocking(False)
        self.external_tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size)
        self.external_tcp_socket.bind((str(self.ip_address), 0))
        self.logger.debug("tcp router %d bound to %s" % (self.router_index, self.external_tcp_socket.getsockname()))

        self.selector.register(self.external_icmp_socket, selectors.EVENT_READ, self.handle_external_connection)
        self.selector.register(self.external_tcp_socket, selectors.EVENT_READ, self.handle_external_connection)

        # Start the select loop
        while True:
            events = self.selector.select()
            for key, mask in events:
                func = key.data
                func(key.fileobj, mask)

    def kill(self):
        self.logger.debug("AAARRRRGGGHH!!!")
        self.logger.info("router {} killed".format(self.router_index + 1))
        import sys
        sys.exit(9)

    def handle_udp_connection(self, connection, mask):
        data, address = connection.recvfrom(self.buffer_size)
        self.logger.debug("UDP packet received {} bytes from {}.".format(len(data), address))

        message = csci551fg.ipfg.IPv4Packet(data)
        ip_proto = message.get_protocol()
        if ip_proto == socket.IPPROTO_ICMP:
            self._handle_imcp(data, address)
        elif ip_proto == csci551fg.ipfg.IPPROTO_MINITOR:
            self.logger.info("pkt from port: %s, length: %s, contents: 0x%s" % (
                address[1], len(message.packet_data[20:]), message.packet_data[20:].hex()))
            self._handle_minitor(data, address)
        else:
            raise Exception(
                "Could not determine message type in router. IP Protocol: %s, Message: %s" % (ip_proto, message))

    def _find_known_circuit(self, id_i):
        return next(iter([c for c in self.circuit_list if c.id_i == id_i]), None)

    def _handle_imcp(self, data, address, ):
        echo_message = csci551fg.ipfg.ICMPEcho(data)

        if self.stage <= 4:
            self.logger.info("ICMP from port: %s, src: %s, dst: %s, type: %s",
                             address[1], echo_message.source_ipv4, echo_message.destination_ipv4,
                             echo_message.icmp_type[0])

        # If the echo is addressed to this router or to the router subnet, reply
        # directly back to the proxy
        if echo_message.destination_ipv4 == self.ip_address \
                or echo_message.destination_ipv4 in self.router_subnet:
            reply = echo_message.reply()
            self.logger.debug("Router replying with data {}".format(reply.packet_data))

            self.udp_connection.sendto(reply.packet_data, address)
        # Otherwise, send it out the external interface
        else:
            outgoing = echo_message.set_source(self.ip_address)
            self.logger.debug(
                "Incoming source %s, Outgoing source %s" % (echo_message.source_ipv4, outgoing.source_ipv4))
            self.external_icmp_socket.sendmsg([outgoing.packet_data[20:]], [], 0, (str(outgoing.destination_ipv4), 0))

    def _handle_minitor(self, data, address):
        mcm_message = csci551fg.ipfg.MCMPacket(data)
        mcm_type = mcm_message.get_message_type()
        self.logger.debug("from {} message {}".format(address, mcm_message))
        if mcm_type == csci551fg.ipfg.MCM_CE:
            self._handle_circuit_extend(data, address)
        elif mcm_type == csci551fg.ipfg.MCM_CED or mcm_type == csci551fg.ipfg.MCM_ECED:
            self._handle_circuit_extend_done(data)
        elif mcm_type == csci551fg.ipfg.MCM_RD:
            self._handle_relay_data(data, address)
        elif mcm_type == csci551fg.ipfg.MCM_RRD:
            self._handle_relay_reply_data(data)
        elif mcm_type == csci551fg.ipfg.MCM_FDH:
            self._handle_fake_diffie_hellman(data, address)
        elif mcm_type == csci551fg.ipfg.MCM_ECE:
            self._handle_encrypted_circuit_extend(data, address)
        elif mcm_type == csci551fg.ipfg.MCM_RED:
            self._handle_relay_data(data, address, encrypted=True)
        elif mcm_type == csci551fg.ipfg.MCM_RRED:
            self._handle_relay_reply_encrypted_data(data)
        elif mcm_type == csci551fg.ipfg.MCM_KR:
            self.kill()
        elif mcm_type == csci551fg.ipfg.MCM_RW:
            self._handle_router_worried(data)
        else:
            raise Exception("Unknown MCM message. Type {}, Message {}".format(hex(mcm_type), mcm_message))

    def _handle_circuit_extend(self, data, address):
        mcm_ce = csci551fg.ipfg.CircuitExtend(data)
        id_i = mcm_ce.get_circuit_id()
        known_circuit = self._find_known_circuit(id_i)
        if known_circuit:
            # Known circuit, forward on
            ce_forward = mcm_ce.forward(known_circuit.id_o)

            self.logger.info(
                "forwarding extend circuit: incoming: {}, outgoing: {} at {}".format(hex(known_circuit.id_i),
                                                                                     hex(known_circuit.id_o),
                                                                                     known_circuit.next_hop))

            self.udp_connection.sendto(ce_forward.packet_data, ('127.0.0.1', known_circuit.next_hop))

        else:
            # New circuit
            id_o = (self.router_index + 1) * 256 + (len(self._circuit_list) + 1)
            (next_hop,) = struct.unpack("!H", mcm_ce.next_hop)
            self.circuit_list.append(CircuitEntry(id_i, id_o, address[1], next_hop, None))
            self.logger.info(
                "new extend circuit: incoming: {}, outgoing {} at {}".format(hex(id_i), hex(id_o), next_hop))

            ced = mcm_ce.reply()

            self.udp_connection.sendto(ced.packet_data, address)

    def _handle_circuit_extend_done(self, data):
        mcm_ced = csci551fg.ipfg.CircuitExtendDone(data)
        id_i = mcm_ced.get_circuit_id()

        known_circuit = next(iter([c for c in self.circuit_list if c.id_o == id_i]), None)
        if known_circuit:
            # Reverse-Forward circuit extend done Messages
            mcm_ced = mcm_ced.set_circuit_id(known_circuit.id_i)

            self.logger.info("forwarding extend-done circuit: incoming: %s, outgoing: %s at %s"
                             % (hex(id_i), hex(known_circuit.id_i), known_circuit.prev_hop))
        else:
            known_circuit = self._find_known_circuit(id_i)

        self.udp_connection.sendto(mcm_ced.packet_data, ('127.0.0.1', known_circuit.prev_hop))

    def _handle_relay_data(self, data, address, encrypted=False):
        mcm_rd = csci551fg.ipfg.RelayData(data)
        id_i = mcm_rd.get_circuit_id()
        known_circuit = self._find_known_circuit(id_i)
        if known_circuit:
            if known_circuit.next_hop != csci551fg.ipfg.LAST_HOP:
                if not encrypted:
                    i_packet = csci551fg.ipfg.IPv4Packet(mcm_rd.contents)
                    self.logger.info(
                        "relay packet, circuit incoming: {}, outgoing: {}, incoming src: {}, outgoing src: {}, dst:{}".format(
                            hex(id_i), hex(known_circuit.id_o), i_packet.source_ipv4, self.ip_address,
                            known_circuit.next_hop)
                    )
                    forward_data = mcm_rd.forward(self.ip_address, known_circuit.id_o)
                    self.udp_connection.sendto(forward_data.packet_data, ('127.0.0.1', known_circuit.next_hop))
                else:
                    mcm_red = csci551fg.ipfg.RelayEncryptedData(mcm_rd.packet_data)
                    mcm_red = mcm_red.set_contents(mcm_red.decrypt_contents(known_circuit.key)) \
                        .forward(None, known_circuit.id_o)

                    self.logger.info(
                        "relay encrypted packet, circuit incoming: {}, outgoing: {}".format(
                            hex(id_i), hex(known_circuit.id_o))
                    )
                    self.udp_connection.sendto(mcm_red.packet_data, ('127.0.0.1', known_circuit.next_hop))
                    if self.stage == 9:
                        response_timer = threading.Timer(5, self._reply_timeout, args=(known_circuit,))
                        response_timer.start()
                        if known_circuit in self.circuit_timer_map:
                            self.circuit_timer_map[known_circuit].cancel()
                        self.circuit_timer_map[known_circuit] = response_timer
                        self.logger.debug("Started timer for circuit {}".format(hex(known_circuit.id_i)))
            else:
                # Send external
                if encrypted:
                    i_packet = csci551fg.ipfg.IPv4Packet(
                        csci551fg.ipfg.RelayEncryptedData(mcm_rd.packet_data).decrypt_contents(known_circuit.key))
                else:
                    i_packet = csci551fg.ipfg.IPv4Packet(mcm_rd.contents)

                ip_proto = i_packet.get_protocol()
                if ip_proto == socket.IPPROTO_ICMP:
                    icmp_packet = csci551fg.ipfg.ICMPEcho(i_packet.packet_data)
                    flow_id = FlowId(self.ip_address, 0, icmp_packet.destination_ipv4, 0, ip_proto)
                    self.logger.debug("Saving flow id {}:{}".format(flow_id, known_circuit))
                    self.flow_map[flow_id] = known_circuit
                    self.logger.info(
                        "outgoing packet, circuit incoming: {}, incoming src: {}, outgoing src: {}, dst: {}".format(
                            hex(id_i), i_packet.source_ipv4, self.ip_address, i_packet.destination_ipv4
                        ))
                    self._handle_imcp(i_packet.packet_data, address)

                elif ip_proto == socket.IPPROTO_TCP:
                    tcp_packet = csci551fg.ipfg.TCPPacket(i_packet.packet_data)

                    incoming_source_ip = tcp_packet.source_ipv4
                    tcp_packet = tcp_packet.set_source(self.ip_address)
                    flow_id = FlowId(tcp_packet.source_ipv4, tcp_packet.get_source_port(), tcp_packet.destination_ipv4,
                                     tcp_packet.get_destination_port(), ip_proto)
                    self.logger.debug("Saving flow id {}:{}".format(flow_id, known_circuit))
                    self.flow_map[flow_id] = known_circuit

                    self.logger.info(
                        "outgoing TCP packet, circuit incoming: {}, incoming src IP/port: {}:{}, "
                        "outgoing src IP/port: {}:{}, dst IP/port: {}:{}, seqno: {}, ackno: {}".format(
                            hex(id_i), incoming_source_ip, tcp_packet.get_source_port(), tcp_packet.source_ipv4,
                            tcp_packet.get_source_port(), tcp_packet.destination_ipv4,
                            tcp_packet.get_destination_port(),
                            tcp_packet.get_sequence_no(), tcp_packet.get_ack_no()
                        ))

                    self.external_tcp_socket.sendto(tcp_packet.packet_data[20:], (str(tcp_packet.destination_ipv4),
                                                                                  tcp_packet.get_destination_port()))
                else:

                    raise Exception("Unknown protocol {}. Packet {}. contents: 0x{}".format(ip_proto, i_packet,
                                                                                            i_packet.packet_data.hex()))
        else:
            packet = csci551fg.ipfg.IPv4Packet(mcm_rd.contents)
            self.logger.info("unknown incoming circuit: {}, src: {}, dst: {}".format(hex(id_i), packet.source_ipv4,
                                                                                     packet.destination_ipv4))

    def _handle_relay_reply_data(self, data):
        mcm_rrd = csci551fg.ipfg.RelayReturnData(data)
        id_i = mcm_rrd.get_circuit_id()
        known_circuit = next(iter([c for c in self.circuit_list if c.id_o == id_i]), None)
        if known_circuit:
            # Reverse-Forward relay reply Messages
            mcm_rrd = mcm_rrd.set_circuit_id(known_circuit.id_i)
        else:
            known_circuit = next(iter([c for c in self.circuit_list if c.id_i == id_i]), None)
            mcm_rrd = mcm_rrd.set_circuit_id(known_circuit.id_i)

        i_packet = csci551fg.ipfg.IPv4Packet(mcm_rrd.contents)
        if i_packet.get_protocol() == socket.IPPROTO_TCP:
            i_packet = csci551fg.ipfg.TCPPacket(i_packet.packet_data)
        o_packet = i_packet.set_destination(ipaddress.IPv4Address('10.0.2.15'))
        mcm_rrd = mcm_rrd.set_contents(o_packet.packet_data)
        self.logger.info(
            "relay reply packet, circuit incoming: {}, outgoing: {}, src: {}, incoming dst: {}, outgoing dst: {}".format(
                hex(id_i), hex(known_circuit.id_i), i_packet.source_ipv4, i_packet.destination_ipv4,
                o_packet.destination_ipv4
            ))
        self.udp_connection.sendto(mcm_rrd.packet_data, ('127.0.0.1', known_circuit.prev_hop))

    def _reply_timeout(self, circuit):
        self.logger.info(
            "router {} worried about {} on circuit {}".format(self.port, circuit.next_hop, hex(circuit.id_i)))
        worried = csci551fg.ipfg.RouterWorried(bytes(25)) \
            .set_circuit_id(circuit.id_i) \
            .set_self_name(self.port) \
            .set_next_name(circuit.next_hop)
        self.logger.debug("{}".format(worried))
        self.udp_connection.sendto(worried.packet_data, ('127.0.0.1', circuit.prev_hop))

    def _handle_relay_reply_encrypted_data(self, data):
        mcm_rred = csci551fg.ipfg.RelayReturnEncryptedData(data)
        id_i = mcm_rred.get_circuit_id()
        known_circuit = next(iter([c for c in self.circuit_list if c.id_o == id_i]), None)
        if known_circuit:
            # Reverse-Forward relay reply Messages
            mcm_rred = mcm_rred.set_circuit_id(known_circuit.id_i)
        else:
            known_circuit = next(iter([c for c in self.circuit_list if c.id_i == id_i]), None)
            mcm_rred = mcm_rred.set_circuit_id(known_circuit.id_i)

        mcm_rred = mcm_rred.encrypt_contents([known_circuit.key], mcm_rred.contents)
        self.logger.info(
            "relay reply packet, circuit incoming: {}, outgoing: {}".format(
                hex(id_i), hex(known_circuit.id_i)
            ))

        if self.stage == 9:
            try:
                self.logger.debug("Cancelling timer for circuit {}".format(known_circuit.id_i))
                self.circuit_timer_map[known_circuit].cancel()
            except Exception as e:
                self.logger.debug("Tried to cancel timer. Got {}".format(e))
        self.udp_connection.sendto(mcm_rred.packet_data, ('127.0.0.1', known_circuit.prev_hop))

    def _handle_router_worried(self, data):
        mcm_rw = csci551fg.ipfg.RouterWorried(data)
        id_i = mcm_rw.get_circuit_id()
        known_circuit = next(iter([c for c in self.circuit_list if c.id_o == id_i]), None)
        if known_circuit:
            # Reverse-Forward relay reply Messages
            mcm_rw = mcm_rw.set_circuit_id(known_circuit.id_i)
        else:
            known_circuit = next(iter([c for c in self.circuit_list if c.id_i == id_i]), None)
            mcm_rw = mcm_rw.set_circuit_id(known_circuit.id_i)

        mcm_rw = mcm_rw.encrypt_contents([known_circuit.key], mcm_rw.contents)
        self.udp_connection.sendto(mcm_rw.packet_data, ('127.0.0.1', known_circuit.prev_hop))

    def _handle_fake_diffie_hellman(self, data, address):
        mcm_fdh = csci551fg.ipfg.FakeDiffieHellman(data)
        id_i = mcm_fdh.get_circuit_id()
        known_circuit = self._find_known_circuit(id_i)
        if known_circuit:
            # Known circuit, decrypt key then forward
            self.logger.debug("known circuit {}".format(known_circuit))
            fdh_forward = mcm_fdh.forward(known_circuit.id_o, known_circuit.key)

            self.logger.info(
                "fake-diffie-hellman, forwarding, circuit incoming: {}, circuit outgoing: {}, key: 0x{}".format(
                    hex(id_i), hex(known_circuit.id_o), fdh_forward.session_key.hex()
                ))

            self.udp_connection.sendto(fdh_forward.packet_data, ('127.0.0.1', known_circuit.next_hop))
        else:
            # New circuit
            id_o = (self.router_index + 1) * 256 + (len(self.circuit_list) + 1)
            (next_hop,) = (None,)
            self.circuit_list.append(CircuitEntry(id_i, id_o, address[1], next_hop, mcm_fdh.session_key))
            self.logger.info("fake-diffie-hellman, new circuit incoming: {}, key: 0x{}".format(
                hex(id_i), mcm_fdh.session_key.hex()
            ))

    def _handle_encrypted_circuit_extend(self, data, address):
        mcm_ece = csci551fg.ipfg.EncryptedCircuitExtend(data)
        id_i = mcm_ece.get_circuit_id()
        known_circuit = self._find_known_circuit(id_i)
        if known_circuit:
            if not known_circuit.next_hop:
                # This message is for us, fill in next hop and reply
                (next_hop,) = struct.unpack("!H", mcm_ece.decrypt_next_hop(known_circuit.key))
                self.logger.debug("decrypted next hop {}".format(next_hop))
                self.circuit_list[self.circuit_list.index(known_circuit)] = CircuitEntry(known_circuit.id_i,
                                                                                         known_circuit.id_o,
                                                                                         known_circuit.prev_hop,
                                                                                         next_hop,
                                                                                         known_circuit.key)
                self.logger.debug("circuit key 0x{} {}".format(self.circuit_list[0].key.hex(), (self.circuit_list,)))
                self.logger.info(
                    "new encrypted extend circuit: incoming: {}, outgoing {} at {}".format(
                        hex(id_i), hex(known_circuit.id_o), next_hop))

                eced = mcm_ece.reply()

                self.udp_connection.sendto(eced.packet_data, address)
            else:
                # This message needs to be forwarded
                (next_hop,) = struct.unpack("!H", mcm_ece.decrypt_next_hop(known_circuit.key))
                ece_forward = mcm_ece.forward(known_circuit.id_o) \
                    .set_next_hop(next_hop)
                self.logger.info("forwarding encrypted extend circuit: incoming: %s, outgoing: %s at %s"
                                 % (hex(known_circuit.id_i), hex(known_circuit.id_o), known_circuit.next_hop))

                self.udp_connection.sendto(ece_forward.packet_data, ('127.0.0.1', known_circuit.next_hop))
        else:
            # Should never happen because diffie should always come first
            raise Exception("Unknown circuit when handling ECE")

    def handle_external_connection(self, external_connection, mask):
        data, address = external_connection.recvfrom(self.buffer_size)
        ip_packet = csci551fg.ipfg.IPv4Packet(data)

        # Only process if it addressed to us
        if ip_packet.destination_ipv4 == self.ip_address:
            if self.stage <= 4:
                echo_message = csci551fg.ipfg.ICMPEcho(data)
                self.info("ICMP from raw sock, src: %s, dst: %s, type: %s",
                          ip_packet.source_ipv4, ip_packet.destination_ipv4, echo_message.icmp_type[0])

                incoming = ip_packet.set_destination(ipaddress.IPv4Address('10.0.2.15'))
                self.udp_connection.sendto(incoming.packet_data, self.proxy_address)
            else:
                if ip_packet.get_protocol() == socket.IPPROTO_ICMP:
                    flow_id = FlowId(ip_packet.destination_ipv4, 0, ip_packet.source_ipv4, 0, ip_packet.get_protocol())
                else:
                    tcp_packet = csci551fg.ipfg.TCPPacket(data)
                    flow_id = FlowId(ip_packet.destination_ipv4, tcp_packet.get_destination_port(),
                                     ip_packet.source_ipv4, tcp_packet.get_source_port(), ip_packet.get_protocol())

                try:
                    return_circuit = self.flow_map[flow_id]
                except KeyError:
                    self.logger.debug("Unknown Flow id: {}".format(flow_id))
                    return

                self.logger.debug("Flow id: {}".format(flow_id))

                if self.stage == 5:
                    rrd = csci551fg.ipfg.RelayReturnData(bytes(23 + len(ip_packet.packet_data)))
                    rrd = rrd.set_contents(ip_packet.packet_data)
                else:
                    if ip_packet.get_protocol() == socket.IPPROTO_TCP:
                        contents = csci551fg.ipfg.TCPPacket(ip_packet.packet_data).set_destination(
                            ipaddress.IPv4Address('0.0.0.0')).packet_data
                    else:
                        contents = ip_packet.set_destination(ipaddress.IPv4Address('0.0.0.0')).packet_data
                    rrd = csci551fg.ipfg.RelayReturnEncryptedData(bytes(23 + len(contents)))
                    rrd = rrd.encrypt_contents([return_circuit.key], contents)
                rrd = rrd.set_circuit_id(return_circuit.id_i)
                self.logger.debug("rrd {} prev_hop {}".format(rrd, ('127.0.0.1', return_circuit.prev_hop)))

                if ip_packet.get_protocol() == socket.IPPROTO_ICMP:
                    self.logger.info("incoming packet, src: {}, dst: {}, outgoing circuit: {}".format(
                        ip_packet.source_ipv4, ip_packet.destination_ipv4, hex(return_circuit.id_i)
                    ))
                elif ip_packet.get_protocol() == socket.IPPROTO_TCP:
                    tcp_packet = csci551fg.ipfg.TCPPacket(data)
                    self.logger.debug("received message on external interface %s" % tcp_packet)
                    self.logger.info("incoming TCP packet, src IP/port: {}:{}, "
                                     "dst IP/port: {}:{}, seqno: {}, ackno: {}, outgoing circuit: {}".format(
                        tcp_packet.source_ipv4, tcp_packet.get_source_port(), tcp_packet.destination_ipv4,
                        tcp_packet.get_destination_port(), tcp_packet.get_sequence_no(), tcp_packet.get_ack_no(),
                        hex(return_circuit.id_i)
                    ))

                self.udp_connection.sendto(rrd.packet_data, ('127.0.0.1', return_circuit.prev_hop))
