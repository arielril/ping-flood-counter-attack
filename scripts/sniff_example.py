import socket
import sys
import struct


def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)


try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                      socket.ntohs(ETH_P_ALL))
except OSError as msg:
    print('Error'+str(msg))
    sys.exit(1)

print('Socket created!')

s.bind(('eth0', 0))

(packet, addr) = s.recvfrom(65536)

eth_length = 14
eth_header = packet[:14]

eth = struct.unpack("!6s6sH", eth_header)

print("MAC Dst: "+bytes_to_mac(eth[0]))
print("MAC Src: "+bytes_to_mac(eth[1]))
print("Type: "+hex(eth[2]))

if eth[2] == 0x0800:
    print("IP Packet")

    iph = struct.unpack("!BBHHHBBH4s4s", packet[eth_length:20+eth_length])
    options = packet[20+eth_length:]

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl*4

    ttl = iph[5]

    protocol = iph[6]

    if protocol == 1:
        print('ICMP proto')
        print('Type:', options[0])
        print('Code:', options[1])

    if protocol == 41:
        print('IPv6 proto')

    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    print("IP Src: "+s_addr)
    print("IP Dst: "+d_addr)
