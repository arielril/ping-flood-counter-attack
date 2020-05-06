import socket
import sys
import struct


"""
Steps:
    1. Read ping packet
    2. Save list of machines
    3. Create a ping request to some machine in the net
    4. Create a function to identify the ping flood attack
    5. Counter attack the ping flood
"""

ETH_P_ALL = 0x0003
ETH_P_SIZE = 65536
ETH_P_IP = 0x0800


ip_dictionary = set({})


def addFoundIP(ip: str):
    if ip not in ip_dictionary:
        ip_dictionary.add(ip)


def getSocket(if_net: str) -> socket:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Socket created!')

    s.bind((if_net, 0))

    return s


def isIP(p_type: hex) -> bool:
    return p_type == ETH_P_IP


def isIcmpReq(tp: int, code: int) -> bool:
    return tp == 8 and code == 0


def isIcmpRep(tp: int, code: int) -> bool:
    return tp == 0 and code == 0


if __name__ == "__main__":
    sock = getSocket('eth0')

    (packet, addr) = sock.recvfrom(ETH_P_SIZE)

    eth_len = 14
    eth_header = packet[:eth_len]

    ether = struct.unpack('!6s6sH', eth_header)

    packet_type = ether[2]

    if isIP(packet_type):
        print('is IP')
        ip_options = packet[20+eth_len:]

        ip_options_type = ip_options[0]
        ip_options_code = ip_options[1]

        if isIcmpReq(ip_options_type, ip_options_code):
            print('icmp req')
            # TODO: add the source ip to the dictionary
