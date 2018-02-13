import ipaddress

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
