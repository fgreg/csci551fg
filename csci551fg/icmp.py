# Copyright 2018, Frank Greguska, All rights reserved.

"""
This file contains a class responsible for parsing an ICMP echo packet and constructing replies
"""
import ipaddress
import struct
import socket

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

    # Ones compliment and mask to the correct size
    checksum = (~checksum) & 0xffff

    # I have no idea why this is needed but it is.
    checksum = checksum - 1

    return struct.pack("!H", checksum)

class ICMPEcho(object):

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

        # ICMP fields
        self.icmp_type = packet_data[20]
        self.icmp_code = packet_data[21]
        self.checksum = packet_data[22:24]
        self.identifier = packet_data[24:26]
        self.sequence_number = packet_data[26:28]

    def __repr__(self):
        # from pprint import pformat
        # return pformat(vars(self))
        ip = ("IP: <version_IHL={}, tos={}, length={}, identification={}, " + \
             "ip_flags_fragment={}, ip_ttl={}, protocol={}, ip_checksum={}, " + \
             "source={}, destination={}>").format(
             self.version_IHL.hex(), self.tos.hex(), self.total_length.hex(), self.identification.hex(),
             self.ip_flags_fragment.hex(), self.ip_ttl.hex(), self.protocol.hex(), self.ip_checksum.hex(),
             self.source_ipv4, self.destination_ipv4)
        icmp = "ICMP: <type={}, code={}, checksum={}, identifier={}, sequence_number={}>".format(
             self.icmp_type, self.icmp_code, self.checksum.hex(), self.identifier.hex(), self.sequence_number.hex())
        return "{}\n{}".format(ip,icmp)

    def set_source(self, source_ipv4):

        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[12:16] = source_ipv4.packed

        new_packet[10:12] = [0,0]
        new_packet[10:12] = ip_icmp_checksum(new_packet[0:20])
        return ICMPEcho(bytes(new_packet))

    def set_destination(self, destination_ipv4):

        new_packet = bytearray(len(self.packet_data))
        new_packet[:] = self.packet_data

        new_packet[16:20] = destination_ipv4.packed

        new_packet[10:12] = [0,0]
        new_packet[10:12] = ip_icmp_checksum(new_packet[0:20])
        return ICMPEcho(bytes(new_packet))


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
        reply_data[20] = 0

        # Retain the rest of the to_bytes
        reply_data[21:] = self.packet_data[21:]

        # recompute the ICMP checksum
        reply_data[22:24] = [0,0]
        reply_data[22:24] = ip_icmp_checksum(reply_data)

        return ICMPEcho(bytes(reply_data))
