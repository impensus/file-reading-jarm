import codecs
import hashlib
import pickle
import time


class PyJarm():
    #Deciphering the extensions in the server hello
    def extract_extension_info(self, data, counter, server_hello_length):
        try:
            #Error handling
            if (data[counter+47] == 11):
                return "|"
            elif (data[counter+50:counter+53] == b"\x0e\xac\x0b") or (data[82:85] == b"\x0f\xf0\x0b"):
                return "|"
            elif counter+42 >= server_hello_length:
                return "|"
            count = 49+counter
            length = int(codecs.encode(data[counter+47:counter+49], 'hex'), 16)
            maximum = length+(count-1)
            types = []
            values = []
            #Collect all extension types and values for later reference
            while count < maximum:
                types.append(data[count:count+2])
                ext_length = int(codecs.encode(data[count+2:count+4], 'hex'), 16)
                if ext_length == 0:
                    count += 4
                    values.append("")
                else:
                    values.append(data[count+4:count+4+ext_length])
                    count += ext_length+4
            result = ""
            #Read application_layer_protocol_negotiation
            alpn = self.find_extension(b"\x00\x10", types, values)
            result += str(alpn)
            result += "|"
            #Add formating hyphens
            add_hyphen = 0
            while add_hyphen < len(types):
                result += codecs.encode(types[add_hyphen], 'hex').decode('ascii')
                add_hyphen += 1
                if add_hyphen == len(types):
                    break
                else:
                    result += "-"
            return result
        #Error handling
        except IndexError as e:
            result = "|"
            return result

    #Matching cipher extensions to values
    def find_extension(self, ext_type, types, values):
        iter = 0
        #For the APLN extension, grab the value in ASCII
        if ext_type == b"\x00\x10":
            while iter < len(types):
                if types[iter] == ext_type:
                    return ((values[iter][3:]).decode())
                iter += 1
        else:
            while iter < len(types):
                if types[iter] == ext_type:
                    return values[iter].hex()
                iter += 1
        return ""

    # If a packet is received, decipher the details
    def read_packet(self, hex_stream):

        # convert hex stream from wireshark to byte array

        byte_array = hex_stream
        try:
            if byte_array == None:
                print('byte array is none')
                return "|||"
            jarm = ""
            # Server hello error
            if byte_array[0] == 21 or byte_array == '0000':
                selected_cipher = b""
                return "|||"
            # Check for server hello
            elif (byte_array[0] == 22) and (byte_array[5] == 2):
                server_hello_length = int.from_bytes(byte_array[3:5], "big")
                counter = byte_array[43]
                # Find server's selected cipher
                selected_cipher = byte_array[counter + 44:counter + 46]
                # Find server's selected version
                version = byte_array[9:11]
                # Format
                jarm += codecs.encode(selected_cipher, 'hex').decode('ascii')
                jarm += "|"
                jarm += codecs.encode(version, 'hex').decode('ascii')
                jarm += "|"
                # Extract extensions
                extensions = (self.extract_extension_info(byte_array, counter, server_hello_length))
                jarm += extensions
                return jarm
            else:
                print('in the else block')
                return "|||"

        except Exception as e:
            print('Exception encountered in read_packet function: ' + e)

    #Custom fuzzy hash
    def jarm_hash(self, jarm_raw):

        #If jarm is empty, 62 zeros for the hash
        if jarm_raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||":
            return "0"*62
        fuzzy_hash = ""

        handshakes = jarm_raw.split(",")
        alpns_and_ext = ""
        for handshake in handshakes:
            components = handshake.split("|")
            #Custom jarm hash includes a fuzzy hash of the ciphers and versions
            fuzzy_hash += self.cipher_bytes(components[0])
            fuzzy_hash += self.version_byte(components[1])
            alpns_and_ext += components[2]
            alpns_and_ext += components[3]
        #Custom jarm hash has the sha256 of alpns and extensions added to the end
        sha256 = (hashlib.sha256(alpns_and_ext.encode())).hexdigest()
        fuzzy_hash += sha256[0:32]
        return fuzzy_hash

    #Fuzzy hash for ciphers is the index number (in hex) of the cipher in the list
    def cipher_bytes(self, cipher):
        if cipher == "":
            return "00"
        list = [b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a", b"\x00\x16", b"\x00\x2f", b"\x00\x33", b"\x00\x35", b"\x00\x39", b"\x00\x3c", b"\x00\x3d", b"\x00\x41", b"\x00\x45", b"\x00\x67", b"\x00\x6b", b"\x00\x84", b"\x00\x88", b"\x00\x9a", b"\x00\x9c", b"\x00\x9d", b"\x00\x9e", b"\x00\x9f", b"\x00\xba", b"\x00\xbe", b"\x00\xc0", b"\x00\xc4", b"\xc0\x07", b"\xc0\x08", b"\xc0\x09", b"\xc0\x0a", b"\xc0\x11", b"\xc0\x12", b"\xc0\x13", b"\xc0\x14", b"\xc0\x23", b"\xc0\x24", b"\xc0\x27", b"\xc0\x28", b"\xc0\x2b", b"\xc0\x2c", b"\xc0\x2f", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x72", b"\xc0\x73", b"\xc0\x76", b"\xc0\x77", b"\xc0\x9c", b"\xc0\x9d", b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1", b"\xc0\xa2", b"\xc0\xa3",  b"\xc0\xac", b"\xc0\xad", b"\xc0\xae", b"\xc0\xaf", b'\xcc\x13', b'\xcc\x14', b'\xcc\xa8', b'\xcc\xa9', b'\x13\x01', b'\x13\x02', b'\x13\x03', b'\x13\x04', b'\x13\x05']
        count = 1
        for bytes in list:
            strtype_bytes = codecs.encode(bytes, 'hex').decode('ascii')
            if cipher == strtype_bytes:
                break
            count += 1
        hexvalue = str(hex(count))[2:]
        #This part must always be two bytes
        if len(hexvalue) < 2:
            return_bytes = "0" + hexvalue
        else:
            return_bytes = hexvalue
        return return_bytes

    #This captures a single version byte based on version
    def version_byte(self, version):
        if version == "":
            return "0"
        options = "abcdef"
        count = int(version[3:4])
        byte = options[count]
        return byte

    def ParseNumber(self, number):
        if number.startswith('0x'):
            return int(number[2:], 16)
        else:
            return int(number)

    def main(self):
        #Select the packets and formats to send
        jarm = ""
        #Assemble, send, and decipher each packet
        iterate = 0
        client_hello = None
        server_hello = None
        file_data = None
        server_hello_list = []

        filepath = r'data/byte_array_of_ja3_from_jarm_scan.txt'
        with open(filepath, 'rb') as fp:
            server_hello_list = pickle.load(fp)

        while iterate < len(server_hello_list):
            ans = self.read_packet(server_hello_list[iterate])
            jarm += ans
            iterate += 1
            if iterate == len(server_hello_list):
                break
            else:
                jarm += ","

        #Fuzzy hash
        result = self.jarm_hash(jarm)
        #Write to file

        #Print to STDOUT
        return result