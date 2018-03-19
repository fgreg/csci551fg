# Copyright 2018, Frank Greguska, All rights reserved.

"""
This file contains a class responsible for parsing an ICMP echo packet and constructing replies
"""
import ipaddress
import struct
import socket

IPPROTO_MINITOR = 253
MCM_CE = 0x52
MCM_CED = 0x53

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
    # Only ICMP headers and data. Add one byte if odd
    if len(reply_data) % 2 == 0:
        checksumdata = reply_data
    else:
        checksumdata = reply_data
        checksumdata.append(0)

    # Combine each 2 bytes into word and then sum
    for i in range(0, len(checksumdata), 2):
        word = int.from_bytes(checksumdata[i:i+2], 'big')
        checksum += word

    # Add carry bits
    checksum += (checksum >> 16)

    # Ones compliment and mask to the correct size
    checksum = (~checksum) & 0xffff

    return struct.pack("!H", checksum)

class IPv4Packet(object):

    def __init__(self, packet_data):
        self.packet_data = packet_data

        #IP fields
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
        ip = ("IP: <version_IHL={}, tos={}, length={}, identification={}, " + \
             "ip_flags_fragment={}, ip_ttl={}, protocol={}, ip_checksum={}, " + \
             "source={}, destination={}>").format(
             self.version_IHL.hex(), self.tos.hex(), self.total_length.hex(), self.identification.hex(),
             self.ip_flags_fragment.hex(), self.ip_ttl.hex(), self.protocol.hex(), self.ip_checksum.hex(),
             self.source_ipv4, self.destination_ipv4)
        return ip

    def set_source(self, source_ipv4):

        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[12:16] = source_ipv4.packed

        new_packet[10:12] = [0,0]
        new_packet[10:12] = ip_icmp_checksum(new_packet[0:20])
        return self.__class__(bytes(new_packet))

    def set_destination(self, destination_ipv4):

        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[16:20] = destination_ipv4.packed

        new_packet[10:12] = [0,0]
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
        return "{}\n{}".format(ip,icmp)

    def reply(self):
        reply_data = bytearray(len(self.packet_data))
        # Keep the first 20 bytes the same
        reply_data[0:20] = self.packet_data[0:20]

        # Swap source and destination ip
        reply_data[12:16] = self.set_source(self.destination_ipv4).source_ipv4.packed
        reply_data[16:20] = self.set_destination(self.source_ipv4).destination_ipv4.packed
        # recompute the IP checksum
        reply_data[10:12] = [0,0]
        reply_data[10:12] = ip_icmp_checksum(reply_data[0:20])

        # Change type to 0
        reply_data[20:21] = [0]

        # Retain the rest of the to_bytes
        reply_data[21:] = self.packet_data[21:]

        # recompute the ICMP checksum
        reply_data[22:24] = [0,0]
        reply_data[22:24] = ip_icmp_checksum(reply_data)

        return ICMPEcho(bytes(reply_data))

class MCMPacket(IPv4Packet):

    def __init__(self, packet_data):
        new_packet = bytearray(len(packet_data))
        new_packet[:] = packet_data

        # Zero out entire IP header
        new_packet[0:20] = [0 for i in range(0,20)]

        # Experimental protocol
        new_packet[9:10] = struct.pack('!B', IPPROTO_MINITOR)

        # Set source and destination
        new_packet[12:16] = ipaddress.IPv4Address('127.0.0.1').packed
        new_packet[16:20] = ipaddress.IPv4Address('127.0.0.1').packed
        super().__init__(bytes(new_packet))

        self.message_type = self.packet_data[20:21]
        self.circuit_id = self.packet_data[21:23]

    def __repr__(self):
        ip = super().__repr__()
        mcm = "MCM: <message_type={}, circuit_id={}>".format(
             self.message_type, self.circuit_id)
        return "{}\n{}".format(ip,mcm)

    def set_message_type(self, message_type):
        new_data = bytearray(len(self.packet_data))
        new_data[:] = self.packet_data

        new_data[20:21] = struct.pack("!B",message_type)

        return self.__class__(new_data)

    def set_circuit_id(self, circuit_id):
        new_data = bytearray(len(self.packet_data))
        new_data[:] = self.packet_data

        new_data[21:23] = struct.pack("!H",circuit_id)

        return self.__class__(new_data)

class CircuitExtend(MCMPacket):

    def __init__(self, packet_data):
        new_packet = bytearray(len(packet_data))
        new_packet[:] = packet_data

        new_packet[20:21] = struct.pack('!B', MCM_CE)

        super().__init__(bytes(new_packet))

        self.next_hop = self.packet_data[23:25]

    def __repr__(self):
        ip_mcm = super().__repr__()
        ce = "CE: <next_hop={}>".format(
             self.next_hop)
        return "{}\n{}".format(ip_mcm,ce)

    def set_next_hop(self, next_hop):
        new_data = bytearray(len(self.packet_data))
        new_data[:] = self.packet_data

        new_data[23:25] = struct.pack("!H",next_hop)

        return self.__class__(new_data)

    def reply(self):
        return CircuitExtendDone(self.packet_data[0:23])

    def forward(self, outgoing_circuit_id):
        ced = CircuitExtend(self.packet_data)
        ced.set_circuit_id(outgoing_circuit_id)
        return ced

class CircuitExtendDone(MCMPacket):

    def __init__(self, packet_data):
        new_packet = bytearray(len(packet_data))
        new_packet[:] = packet_data

        new_packet[20:21] = struct.pack('!B', MCM_CED)

        super().__init__(bytes(new_packet))

    def __repr__(self):
        ip_mcm = super().__repr__()
        ced = "CED: <>"
        return "{}\n{}".format(ip_mcm,ced)
