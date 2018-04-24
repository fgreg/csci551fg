# Copyright 2018, Frank Greguska, All rights reserved.

"""
Functions in this file:
    ip_icmp_checksum

This file contains a class responsible for parsing an ICMP echo packet and constructing replies
"""
import ipaddress
import struct

import csci551fg.crypto

IPPROTO_MINITOR = 253
MCM_CE = 0x52
MCM_ECE = 0x62
MCM_CED = 0x53
MCM_ECED = 0x63
MCM_RD = 0x51
MCM_RED = 0x61
MCM_RRD = 0x54
MCM_RRED = 0x64

MCM_FDH = 0x65

LAST_HOP = 65535


def ip_icmp_checksum(data):
    """
    data must already have checksum bytes set to 0
    """

    reply_data = bytearray(len(data))
    reply_data[:] = data

    # Recompute checksum

    #   The checksum is the 16-bit ones's complement of the one's
    # complement sum of the ICMP message starting with the ICMP Type.
    # For computing the checksum , the checksum field should be zero.
    # If the total length is odd, the received data is padded with one
    # octet of zeros for computing the checksum. - https://tools.ietf.org/html/rfc792

    # I don't get it. https://stackoverflow.com/questions/20247551/icmp-echo-checksum
    checksum = 0
    # Add one byte if odd
    if len(reply_data) % 2 == 0:
        checksumdata = reply_data
    else:
        checksumdata = reply_data
        checksumdata.append(0)

    # Combine each 2 bytes into word and then sum
    for i in range(0, len(checksumdata), 2):
        word = struct.unpack(">H", checksumdata[i:i + 2])[0]
        checksum += word

    # Add carry bits
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)

    # Ones compliment and mask to the correct size
    checksum = (~checksum) & 0xffff

    return struct.pack("!H", checksum)


class IPv4Packet(object):

    def __init__(self, packet_data):
        self.packet_data = packet_data

        # IP fields
        self.version_IHL = packet_data[0:1]
        self.tos = packet_data[1:2]
        self.total_length = packet_data[2:4]
        self.identification = packet_data[4:6]
        self.ip_flags_fragment = packet_data[6:8]
        self.ip_ttl = packet_data[8:9]
        self.protocol = packet_data[9:10]
        self.ip_checksum = packet_data[10:12]
        self.source_ipv4 = ipaddress.IPv4Address(packet_data[12:16])
        self.destination_ipv4 = ipaddress.IPv4Address(packet_data[16:20])

    def __repr__(self):
        ip = ("IP: <version_IHL=0x{}, tos=0x{}, length=0x{}, identification=0x{}, " + \
              "ip_flags_fragment=0x{}, ip_ttl=0x{}, protocol=0x{}, ip_checksum=0x{}, " + \
              "source={}, destination={}>").format(
            self.version_IHL.hex(), self.tos.hex(), self.total_length.hex(), self.identification.hex(),
            self.ip_flags_fragment.hex(), self.ip_ttl.hex(), self.protocol.hex(), self.ip_checksum.hex(),
            self.source_ipv4, self.destination_ipv4)
        return ip

    def get_protocol(self):
        return struct.unpack("!B", self.protocol)[0]

    def set_source(self, source_ipv4):
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[12:16] = source_ipv4.packed

        new_packet[10:12] = [0, 0]
        new_packet[10:12] = ip_icmp_checksum(new_packet[0:20])
        return self.__class__(bytes(new_packet))

    def set_destination(self, destination_ipv4):
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[16:20] = destination_ipv4.packed

        new_packet[10:12] = [0, 0]
        new_packet[10:12] = ip_icmp_checksum(new_packet[0:20])
        return self.__class__(bytes(new_packet))


class ICMPEcho(IPv4Packet):

    def __init__(self, packet_data):
        super().__init__(packet_data)

        # ICMP fields
        self.icmp_type = packet_data[20:21]
        self.icmp_code = packet_data[21:22]
        self.checksum = packet_data[22:24]
        self.identifier = packet_data[24:26]
        self.sequence_number = packet_data[26:28]

    def __repr__(self):
        ip = super().__repr__()
        icmp = "ICMP: <type={}, code={}, checksum={}, identifier={}, sequence_number={}>".format(
            self.icmp_type, self.icmp_code, self.checksum.hex(), self.identifier.hex(), self.sequence_number.hex())
        return "{}\n{}".format(ip, icmp)

    def reply(self):
        reply_data = bytearray(len(self.packet_data))
        # Keep the first 20 bytes the same
        reply_data[0:20] = self.packet_data[0:20]

        # Swap source and destination ip
        reply_data[12:16] = self.set_source(self.destination_ipv4).source_ipv4.packed
        reply_data[16:20] = self.set_destination(self.source_ipv4).destination_ipv4.packed
        # recompute the IP checksum
        reply_data[10:12] = [0, 0]
        reply_data[10:12] = ip_icmp_checksum(reply_data[0:20])

        # Change type to 0
        reply_data[20:21] = [0]

        # Retain the rest of the to_bytes
        reply_data[21:] = self.packet_data[21:]

        # recompute the ICMP checksum
        reply_data[22:24] = [0, 0]
        reply_data[22:24] = ip_icmp_checksum(reply_data)

        return ICMPEcho(bytes(reply_data))


class TCPPacket(IPv4Packet):

    def __init__(self, packet_data):
        super().__init__(packet_data)

        # TCP fields
        self.source_port = packet_data[20:22]
        self.destination_port = packet_data[22:24]
        self.sequence_no = packet_data[24:28]
        self.ack_no = packet_data[28:32]
        self.data_offset_reserved = struct.pack("!B", (struct.unpack("!B", packet_data[32:33])[0] & ~(1 << 0)))
        self.tcp_flags = struct.pack("!H", (struct.unpack("!H", packet_data[32:34])[0] & 0x1ff))
        self.window_size = packet_data[34:36]
        self.tcp_checksum = packet_data[36:38]
        self.urgent = packet_data[38:40]

    def __repr__(self):
        ip = super().__repr__()
        tcp = "TCP: <source_port={}, destination_port={}, sequence_no={}, ack_no={}, data_offset_reserved=0x{}, " \
              "tcp_flags=0x{}, window_size=0x{}, tcp_checksum=0x{}, urgent=0x{}>".format(
            self.get_source_port(), self.get_destination_port(), self.get_sequence_no(), self.get_ack_no(),
            self.data_offset_reserved.hex(),
            self.tcp_flags.hex(), self.window_size.hex(), self.tcp_checksum.hex(), self.urgent.hex())
        return "{}\n{}".format(ip, tcp)

    def get_source_port(self):
        return struct.unpack("!H", self.source_port)[0]

    def get_destination_port(self):
        return struct.unpack("!H", self.destination_port)[0]

    def get_sequence_no(self):
        return struct.unpack("!I", self.sequence_no)[0]

    def get_ack_no(self):
        return struct.unpack("!I", self.ack_no)[0]

    @staticmethod
    def _checksum(packet_data):
        new_packet = TCPPacket(packet_data)

        checksum_data = bytearray(12 + len(new_packet.packet_data[20:]))
        checksum_data[0:4] = new_packet.source_ipv4.packed
        checksum_data[4:8] = new_packet.destination_ipv4.packed
        checksum_data[8:9] = [0]
        checksum_data[9:10] = struct.pack("!B", new_packet.get_protocol())
        checksum_data[10:12] = struct.pack("!H", len(new_packet.packet_data[20:]))
        checksum_data[12:] = new_packet.packet_data[20:]
        checksum_data[28:30] = [0, 0]

        new_packet_data = bytearray(len(new_packet.packet_data))
        new_packet_data[:] = new_packet.packet_data

        checksum = ip_icmp_checksum(checksum_data)
        new_packet_data[36:38] = checksum

        # print("packet data 0x{}\n"
        #       "len checksum_data {}\n"
        #       "source ip {}\t0x{}\n"
        #       "dest ip {}\t0x{}\n"
        #       "reserved 0x{}\n"
        #       "protocol 0x{}\n"
        #       "length {}\t0x{}\n"
        #       "tcp header and data len {} 0x{}\n"
        #       "checksum 0x{}\n"
        #       "new packet data 0x{}\n"
        #       "new checksum 0x{}\n".format(
        #     packet_data.hex(),
        #     len(checksum_data),
        #     new_packet.source_ipv4, checksum_data[0:4].hex(),
        #     new_packet.destination_ipv4, checksum_data[4:8].hex(),
        #     checksum_data[8:9].hex(),
        #     checksum_data[9:10].hex(),
        #     struct.unpack("!H", checksum_data[10:12])[0], checksum_data[10:12].hex(),
        #     len(new_packet.packet_data), checksum_data[12:].hex(),
        #     checksum_data[48:50].hex(),
        #     new_packet_data.hex(),
        #     new_packet_data[36:38].hex()
        # ))

        return new_packet_data

    def set_source(self, source_ipv4):
        new_packet_data = TCPPacket._checksum(super().set_source(source_ipv4).packet_data)

        return self.__class__(bytes(new_packet_data))

    def set_destination(self, destination_ipv4):
        new_packet_data = TCPPacket._checksum(super().set_destination(destination_ipv4).packet_data)

        return self.__class__(bytes(new_packet_data))


class MCMPacket(IPv4Packet):

    def __init__(self, packet_data):
        super().__init__(packet_data)
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        # Zero out entire IP header
        new_packet[0:20] = [0 for i in range(0, 20)]

        # Experimental protocol
        new_packet[9:10] = struct.pack('!B', IPPROTO_MINITOR)

        # Set source and destination
        new_packet[12:16] = ipaddress.IPv4Address('127.0.0.1').packed
        new_packet[16:20] = ipaddress.IPv4Address('127.0.0.1').packed

        self.packet_data = bytes(new_packet)
        self.message_type = self.packet_data[20:21]
        self.circuit_id = self.packet_data[21:23]

    def __repr__(self):
        ip = super().__repr__()
        mcm = "MCM: <message_type=0x{}, circuit_id=0x{}>".format(
            self.message_type.hex(), self.circuit_id.hex())
        return "{}\n{}".format(ip, mcm)

    def get_message_type(self):
        return struct.unpack("!B", self.message_type)[0]

    def get_circuit_id(self):
        return struct.unpack("!H", self.circuit_id)[0]

    def set_message_type(self, message_type):
        new_data = bytearray(len(self.packet_data))
        new_data[:] = self.packet_data

        new_data[20:21] = struct.pack("!B", message_type)

        return self.__class__(bytes(new_data))

    def set_circuit_id(self, circuit_id):
        new_data = bytearray(len(self.packet_data))
        new_data[:] = self.packet_data

        new_data[21:23] = struct.pack("!H", circuit_id)

        return self.__class__(bytes(new_data))


class CircuitExtend(MCMPacket):

    def __init__(self, packet_data):
        super().__init__(packet_data)
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[20:21] = struct.pack('!B', MCM_CE)

        self.packet_data = bytes(new_packet)
        self.next_hop = self.packet_data[23:25]

    def __repr__(self):
        ip_mcm = super().__repr__()
        ce = "CE: <next_hop=0x{}>".format(
            self.next_hop.hex())
        return "{}\n{}".format(ip_mcm, ce)

    def set_next_hop(self, next_hop, packed=False):
        new_data = bytearray(len(self.packet_data))
        new_data[:] = self.packet_data

        if not packed:
            new_data[23:25] = struct.pack("!H", next_hop)
        else:
            new_data[23:25] = next_hop

        return self.__class__(bytes(new_data))

    def reply(self):
        return CircuitExtendDone(self.packet_data[0:23])

    def forward(self, outgoing_circuit_id):
        ce = CircuitExtend(self.packet_data) \
            .set_circuit_id(outgoing_circuit_id)
        return ce


class EncryptedCircuitExtend(CircuitExtend):
    def __init__(self, packet_data):
        super().__init__(packet_data)
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[20:21] = struct.pack('!B', MCM_ECE)

        self.packet_data = (bytes(new_packet))

    def __repr__(self):
        ip_mcm_ce = super().__repr__()
        ece = "ECE: <>"
        return "{}\n{}".format(ip_mcm_ce, ece)

    def decrypt_next_hop(self, key):
        return csci551fg.crypto.onion_decrypt(key, self.next_hop)

    def encrypt_next_hop(self, next_hop, keys):
        new_data = bytearray(len(self.packet_data))
        new_data[:] = self.packet_data

        new_data[23:25] = struct.pack("!H", csci551fg.crypto.onion_encrypt(keys, next_hop))

        return self.__class__(bytes(new_data))

    def reply(self):
        return EncryptedCircuitExtendDone(self.packet_data[0:23])

    def forward(self, outgoing_circuit_id):
        ece = EncryptedCircuitExtend(self.packet_data) \
            .set_circuit_id(outgoing_circuit_id)
        return ece


class CircuitExtendDone(MCMPacket):

    def __init__(self, packet_data):
        super().__init__(packet_data)
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[20:21] = struct.pack('!B', MCM_CED)

        self.packet_data = (bytes(new_packet))

    def __repr__(self):
        ip_mcm = super().__repr__()
        ced = "CED: <>"
        return "{}\n{}".format(ip_mcm, ced)


class EncryptedCircuitExtendDone(CircuitExtendDone):

    def __init__(self, packet_data):
        super().__init__(packet_data)
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[20:21] = struct.pack('!B', MCM_ECED)

        self.packet_data = (bytes(new_packet))

    def __repr__(self):
        ip_mcm_ced = super().__repr__()
        eced = "ECED: <>"
        return "{}\n{}".format(ip_mcm_ced, eced)


class RelayData(MCMPacket):

    def __init__(self, packet_data):
        super().__init__(packet_data)
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[20:21] = struct.pack('!B', MCM_RD)

        self.packet_data = (bytes(new_packet))
        self.contents = self.packet_data[23:]

    def __repr__(self):
        ip_mcm = super().__repr__()
        rd = "RD: <contents=0x{}>".format(self.contents.hex())
        return "{}\n{}".format(ip_mcm, rd)

    def set_contents(self, contents):
        new_data = bytearray(23 + len(contents))
        new_data[:] = self.packet_data[0:23]

        new_data[23:] = contents

        return self.__class__(bytes(new_data))

    def forward(self, router_ip, outgoing_circuit_id):
        rd = RelayData(self.packet_data)
        rd = rd.set_circuit_id(outgoing_circuit_id)
        packet = IPv4Packet(self.contents)
        packet = packet.set_source(router_ip)
        rd = rd.set_contents(packet.packet_data)
        return rd


class RelayEncryptedData(RelayData):
    def __init__(self, packet_data):
        super().__init__(packet_data)
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[20:21] = struct.pack('!B', MCM_RED)

        self.packet_data = (bytes(new_packet))

    def __repr__(self):
        ip_mcm_rd = super().__repr__()
        red = "RED: <>".format(self.contents)
        return "{}\n{}".format(ip_mcm_rd, red)

    def decrypt_contents(self, key):
        return csci551fg.crypto.onion_decrypt(key, self.contents)

    def encrypt_contents(self, keys, contents):
        contents = csci551fg.crypto.onion_encrypt(keys, contents)
        new_data = bytearray(23 + len(contents))
        new_data[:] = self.packet_data[0:23]

        new_data[23:] = contents

        return self.__class__(bytes(new_data))

    def forward(self, router_ip, outgoing_circuit_id):
        red = RelayEncryptedData(self.packet_data) \
            .set_circuit_id(outgoing_circuit_id)
        return red


class RelayReturnData(MCMPacket):

    def __init__(self, packet_data):
        super().__init__(packet_data)
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[20:21] = struct.pack('!B', MCM_RRD)

        self.packet_data = (bytes(new_packet))
        self.contents = self.packet_data[23:]

    def __repr__(self):
        ip_mcm = super().__repr__()
        rrd = "RRD: <contents={}>".format(self.contents)
        return "{}\n{}".format(ip_mcm, rrd)

    def set_contents(self, contents):
        new_data = bytearray(23 + len(contents))
        new_data[:] = self.packet_data[0:23]

        new_data[23:] = contents

        return self.__class__(bytes(new_data))


class RelayReturnEncryptedData(RelayReturnData):

    def __init__(self, packet_data):
        super().__init__(packet_data)
        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[20:21] = struct.pack('!B', MCM_RRED)

        self.packet_data = (bytes(new_packet))
        self.contents = self.packet_data[23:]

    def __repr__(self):
        ip_mcm_rrd = super().__repr__()
        rred = "RRED: <>".format(self.contents)
        return "{}\n{}".format(ip_mcm_rrd, rred)

    def decrypt_contents(self, key):
        return csci551fg.crypto.onion_decrypt(key, self.contents)

    def encrypt_contents(self, keys, contents):
        contents = csci551fg.crypto.onion_encrypt(keys, contents)
        new_data = bytearray(23 + len(contents))
        new_data[:] = self.packet_data[0:23]

        new_data[23:] = contents

        return self.__class__(bytes(new_data))


class FakeDiffieHellman(MCMPacket):
    def __init__(self, packet_data):
        new_packet = bytearray(len(packet_data))
        new_packet[:] = packet_data

        new_packet[20:21] = struct.pack('!B', MCM_FDH)

        super().__init__(bytes(new_packet))

        self.session_key = self.packet_data[23:39]

    def __repr__(self):
        ip_mcm = super().__repr__()
        fdh = "FDH: <session_key={}>".format(self.session_key)
        return "{}\n{}".format(ip_mcm, fdh)

    def set_session_key(self, session_key):
        new_data = bytearray(39)
        new_data[:] = self.packet_data[0:23]

        new_data[23:] = struct.pack("!16s", session_key)

        return self.__class__(bytes(new_data))

    def forward(self, circuit_id, key):
        fdh = FakeDiffieHellman(self.packet_data) \
            .set_circuit_id(circuit_id) \
            .set_session_key(csci551fg.crypto.onion_decrypt(key, self.session_key))

        return fdh
