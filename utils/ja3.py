#!/usr/bin/env python
"""Generate JA3 fingerprints from PCAPs using Python."""

import argparse
import dpkt
import json
import time
import socket
import struct
import os
from hashlib import md5

GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}
# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
SSL_PORT = 443
TLS_HANDSHAKE = 22


class PyJa3():
    def __init__(self, pcap, known_jarm_scan_ja3_hash_list):
        self.pcap = pcap
        self.known_jarm_scan_ja3_hash_list = known_jarm_scan_ja3_hash_list

    def convert_ip(self, value):
        """Convert an IP address from binary to text.

        :param value: Raw binary data to convert
        :type value: str
        :returns: str
        """
        try:
            return socket.inet_ntop(socket.AF_INET, value)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, value)

    def parse_variable_array(self, buf, byte_len):
        """Unpack data from buffer of specific length.

        :param buf: Buffer to operate on
        :type buf: bytes
        :param byte_len: Length to process
        :type byte_len: int
        :returns: bytes, int
        """
        _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
        assert byte_len <= 4
        size_format = _SIZE_FORMATS[byte_len - 1]
        padding = b'\x00' if byte_len == 3 else b''
        size = struct.unpack(size_format, padding + buf[:byte_len])[0]
        data = buf[byte_len:byte_len + size]

        return data, size + byte_len

    def ntoh(self, buf):
        """Convert to network order.

        :param buf: Bytes to convert
        :type buf: bytearray
        :returns: int
        """
        if len(buf) == 1:
            return buf[0]
        elif len(buf) == 2:
            return struct.unpack('!H', buf)[0]
        elif len(buf) == 4:
            return struct.unpack('!I', buf)[0]
        else:
            raise ValueError('Invalid input buffer size for NTOH')

    def convert_to_ja3_segment(self, data, element_width):
        """Convert a packed array of elements to a JA3 segment.

        :param data: Current PCAP buffer item
        :type: str
        :param element_width: Byte count to process at a time
        :type element_width: int
        :returns: str
        """
        int_vals = list()
        data = bytearray(data)
        if len(data) % element_width:
            message = '{count} is not a multiple of {width}'
            message = message.format(count=len(data), width=element_width)
            raise ValueError(message)

        for i in range(0, len(data), element_width):
            element = self.ntoh(data[i: i + element_width])
            if element not in GREASE_TABLE:
                int_vals.append(element)

        return "-".join(str(x) for x in int_vals)

    def process_extensions(self, client_handshake):
        """Process any extra extensions and convert to a JA3 segment.

        :param client_handshake: Handshake data from the packet
        :type client_handshake: dpkt.ssl.TLSClientHello
        :returns: list
        """
        if not hasattr(client_handshake, "extensions"):
            # Needed to preserve commas on the join
            return ["", "", ""]

        exts = list()
        elliptic_curve = ""
        elliptic_curve_point_format = ""
        for ext_val, ext_data in client_handshake.extensions:
            if not GREASE_TABLE.get(ext_val):
                exts.append(ext_val)
            if ext_val == 0x0a:
                a, b = self.parse_variable_array(ext_data, 2)
                # Elliptic curve points (16 bit values)
                elliptic_curve = self.convert_to_ja3_segment(a, 2)
            elif ext_val == 0x0b:
                a, b = self.parse_variable_array(ext_data, 1)
                # Elliptic curve point formats (8 bit values)
                elliptic_curve_point_format = self.convert_to_ja3_segment(a, 1)
            else:
                continue

        results = list()
        results.append("-".join([str(x) for x in exts]))
        results.append(elliptic_curve)
        results.append(elliptic_curve_point_format)
        return results

    def process_pcap(self, pcap, any_port=False):
        """Process packets within the PCAP.

        :param pcap: Opened PCAP file to be processed
        :type pcap: dpkt.pcap.Reader
        :param any_port: Whether or not to search for non-SSL ports
        :type any_port: bool
        """

        server_hello_list = []

        iterate = 0
        current_pointer = 0  # Pointer to tell us which TLS record type we were and are currently looking at
        previous_pointer = 0  # 1 == client hello, 2 == server hello
        mutex = 0  # Used as a 'logic gate' to block certain code running when not required
        checked_ja3_and_alpn = 0
        current_ja3_match_mutex = 0
        previous_ja3_match_mutex = 0

        # Legacy ja3 function stuff.
        decoder = dpkt.ethernet.Ethernet
        linktype = pcap.datalink()
        if linktype == dpkt.pcap.DLT_LINUX_SLL:
            decoder = dpkt.sll.SLL
        elif linktype == dpkt.pcap.DLT_NULL or linktype == dpkt.pcap.DLT_LOOP:
            decoder = dpkt.loopback.Loopback

        results = list()
        for timestamp, buf in pcap:
            try:
                eth = decoder(buf)
            except Exception:
                continue

            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                # We want an IP packet
                continue
            if not isinstance(eth.data.data, dpkt.tcp.TCP):
                # TCP only
                continue

            ip = eth.data
            tcp = ip.data

            if not (tcp.dport == SSL_PORT or tcp.sport == SSL_PORT or any_port):
                # Doesn't match SSL port or we are picky
                continue
            if len(tcp.data) <= 0:
                continue

            tls_handshake = bytearray(tcp.data)
            if tls_handshake[0] != TLS_HANDSHAKE:
                continue

            try:
                records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)

            except dpkt.ssl.SSL3Exception:
                continue
            except dpkt.dpkt.NeedData:
                continue

            if len(records) <= 0:
                continue

            # We want a new array to store only the packets which are client or server hellos (ignoring type 11, 12, 14 and 32)
            new_record_array = []
            for record in records:
                client_hello = bytearray(record.data)
                if client_hello[0] == 11 or client_hello[0] == 12 or client_hello[0] == 14 or client_hello[0] == 32:
                    continue
                else:
                    new_record_array.append(record)

            # Loop through the new data
            for record in new_record_array:
                hellos = (bytearray(record.data))  # bytearray the client/server hellos

                if (hellos[0] == 1):  # start off the function by setting current pointer.
                    current_pointer = 1  # We don't do anything else in here as we only care about client_hellos from an ordering perspective

                    try:
                        handshake = dpkt.ssl.TLSHandshake(record.data)
                    except dpkt.dpkt.NeedData:
                        # Looking for a handshake here
                        continue
                    if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                        # Still not the HELLO
                        continue

                    client_handshake = handshake.data
                    buf, ptr = self.parse_variable_array(client_handshake.data, 1)
                    buf, ptr = self.parse_variable_array(client_handshake.data[ptr:], 2)
                    ja3 = [str(client_handshake.version)]

                    # Cipher Suites (16 bit values)
                    ja3.append(self.convert_to_ja3_segment(buf, 2))
                    ja3 += self.process_extensions(client_handshake)
                    ja3 = ",".join(ja3)

                    calculated_ja3_hash = md5(ja3.encode()).hexdigest()
                    if calculated_ja3_hash in self.known_jarm_scan_ja3_hash_list and "spdy" in str(record.data).lower():
                        checked_ja3_and_alpn = 1
                    else:
                        checked_ja3_and_alpn = 0
                    if (checked_ja3_and_alpn == 1):
                        current_ja3_match_mutex = 1
                    else:
                        current_ja3_match_mutex = 0

                if (hellos[0] == 2):
                    current_pointer = 2

                if(hellos[0] != 1 and hellos[0] != 2):
                    continue
                """
                The logic here is used to loop through records in the array (which could be a client hello or server hello) 
                and map the client hello to the corresponding server hello.

                However, if a client hello is missing a response, the next index will just be another client hello so we 
                need a way to recognise this and add '0000' to the array of server hello data (in order to keep the integrity).
                """

                # If we are looking at a server hello, and the last was a client hello
                if (previous_pointer == 1 and current_pointer == 2):
                    previous_ja3_match_mutex = current_ja3_match_mutex
                    if(previous_ja3_match_mutex == 1):
                        handshake = dpkt.ssl.TLSHandshake(
                            record.data)  # Extract some of the handshake metadata used to build the full TLS record.

                        # Content type is always '16' in hex. We use hex initially as analysts often use hex streams in wireshark and its easier to debug PCAPs by analysing hex strings
                        tls_content_type = bytes.fromhex(
                            '16')  # We then convert to bytes which is more logical and easier to use in Python and JARM

                        tls_version_int = int(
                            handshake.data.version)  # Get the TLS version from the handshake (already an int so no need to hex convert)
                        tls_version_bytes = struct.pack('H', tls_version_int)  # Convert to bytes

                        tls_length_int = int(
                            handshake.length) + 4  # Similarly, already an int so no need to hex convert
                        tls_length_bytes = struct.pack('>H',
                                                       tls_length_int)  # Convert to bytes with an extra 00 appended (>H operator takes the byte value and places to 4 bits)

                        # record.data is simply the rest of the content of the packet without the metadata headers
                        content = record.data

                        # We have to rebuild the full bytestream of the packet using the metadata and content
                        full_server_hello_bytes = tls_content_type + tls_version_bytes + tls_length_bytes + content

                        # We add this to an array which just contains all server hellos (without any of the missing values)
                        server_hello_list.append(full_server_hello_bytes)
                        ja3_match_mutex = 0

                    previous_pointer = current_pointer  # Reset the pointer as we are moving on
                    mutex += 1  # Increment the mutex so none of the other code runs and matches after changing the pointers

                # If we are looking at a client hello and the previous was a client hello, this means the previous was a hello without a server hello
                if (previous_pointer == 1 and current_pointer == 1 and mutex == 0):  # Mutex must be zero so previous code wasn't matching and modifying values
                    previous_pointer = current_pointer  # Update pointers
                    mutex += 1

                    if(previous_ja3_match_mutex == 1):
                        server_hello_list.append('0000')

                # Rest of the code is for just correctly updating pointers
                if (previous_pointer == 2 and current_pointer == 1 and mutex == 0):
                    previous_pointer = current_pointer
                    mutex += 1

                if (previous_pointer == 0 and current_pointer == 1 and mutex == 0):
                    previous_pointer = current_pointer
                    mutex += 1

                iterate += 1
            mutex = 0
        # Account for last iteration of packets being a client hello with no server response.
        if current_pointer == 1 and previous_pointer == 1:
            if previous_ja3_match_mutex == 1:
                server_hello_list.append('0000')

        return server_hello_list  # The output of the script is this human readable hex stream of the full server hellos, including missing elements.

    def main(self):
        # Use an iterator to process each line of the file
        output = None
        with open(self.pcap, 'rb') as fp:
            try:
                capture = dpkt.pcap.Reader(fp)
            except ValueError as e_pcap:
                try:
                    fp.seek(0, os.SEEK_SET)
                    capture = dpkt.pcapng.Reader(fp)
                except ValueError as e_pcapng:
                    raise Exception(
                        "File doesn't appear to be a PCAP or PCAPng: %s, %s" %
                        (e_pcap, e_pcapng))
            output = self.process_pcap(capture)

            return output