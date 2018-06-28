import socket, binascii

# MAC server discovery by BigNerd95

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind(("0.0.0.0", 5678))

sock.sendto(b"\x00\x00\x00\x00", ("255.255.255.255", 5678))

print("Looking for Mikrotik devices (MAC servers)\n")

while True:
    data, addr = sock.recvfrom(1024)
    if b"\x00\x01\x00\x06" in data:
        start = data.index(b"\x00\x01\x00\x06") + 4
        mac = data[start:start+6]
        #print(addr[0])
        print('\t' + ':'.join('%02x' % b for b in mac))
        print()

        