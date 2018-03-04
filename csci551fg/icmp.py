# Copyright 2018, Frank Greguska, All rights reserved.

"""
This file contains a class responsible for parsing an ICMP echo packet and constructing replies
"""
import ipaddress
import struct

class ICMPEcho(object):

    def __init__(self, packet_data):

        self.packet_data = packet_data

        #IP fields
        self.source_ipv4 = ipaddress.IPv4Address(packet_data[12:16])
        self.destination_ipv4 = ipaddress.IPv4Address(packet_data[16:20])

        # ICMP fields
        self.icmp_type = packet_data[20]
        self.icmp_code = packet_data[21]
        self.checksum = packet_data[22:24]
        self.identifier = packet_data[24:26]
        self.sequence_number = packet_data[26:28]

    def __repr__(self):
        return "<source=%s, destination=%s, type=%s, code=%s, checksum=%s, identifier=%s, sequence_number=%s>" \
            % (self.source_ipv4, self.destination_ipv4, self.icmp_type,
            self.icmp_code, self.checksum, self.identifier, self.sequence_number)

    def set_source(self, source_ipv4):
        pass

    def reply(self):
        reply_data = bytearray(len(self.packet_data))
        # Keep the first 20 bytes the same
        reply_data[0:12] = self.packet_data[0:12]

        # Swap source and destination ip
        reply_data[12:16] = self.packet_data[16:20]
        reply_data[16:20] = self.packet_data[12:16]

        # Change type to 0
        reply_data[20] = 0

        # Retain the rest of the to_bytes
        reply_data[21:] = self.packet_data[21:]

        reply_data = self._checksum(reply_data)

        return ICMPEcho(bytes(reply_data))

    def _checksum(self, packet_data):

        reply_data = packet_data

        # Recompute checksum

        #   The checksum is the 16-bit ones's complement of the one's
        # complement sum of the ICMP message starting with the ICMP Type.
        # For computing the checksum , the checksum field should be zero.
        # If the total length is odd, the received data is padded with one
        # octet of zeros for computing the checksum. - https://tools.ietf.org/html/rfc792

        # I don't get it. https://stackoverflow.com/questions/20247551/icmp-echo-checksum
        reply_data[22] = 0 & 0xf
        reply_data[23] = 0 & 0xf

        checksum = 0
        # Only ICMP headers and data. Add one byte if odd
        if len(reply_data[20:]) % 2 == 0:
            checksumdata = reply_data[20:]
        else:
            checksumdata.append(0)

        # Combine each 2 bytes into word and then sum
        for i in range(0, len(checksumdata), 2):
            word = int.from_bytes(checksumdata[i:i+2], 'big')
            checksum += word

        # Ones compliment and mask to the correct size
        checksum = ~checksum & 0xffff

        reply_data[22:24] = struct.pack(">H", checksum)

        return reply_data
