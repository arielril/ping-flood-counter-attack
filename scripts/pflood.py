from datetime import datetime as dt
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

IP_PROTO_ICMP = 1

# TODO save the frequency of package receiving from each IP
ip_dictionary = dict({})


# TODO check this computation if it is ok
def computeFrequency(ip: str) -> int:
    now = dt.now()
    lastTime = ip_dictionary[ip]['lastTime']
    elapsed = now - lastTime
    pktCount = ip_dictionary[ip]['pktCount']
    return pktCount / elapsed.total_seconds()


def addFoundIPAndCalcFreq(ip: str):
    if ip not in ip_dictionary.keys():
        ip_dictionary[ip] = {
            'lastTime': dt.now(),
            'frequency': 0,
            'pktCount': 1
        }
    else:
        ip_dictionary[ip]['lastTime'] = dt.now()
        ip_dictionary[ip]['pktCount'] += 1

# TODO verify if the pkt count must be resetted here


def updatePktFrequency():
    for ip in ip_dictionary.keys():
        ip_dictionary[ip]['frequency'] = computeFrequency(ip)


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

    lastExec = dt.now()

    while True:
        (packet, addr) = sock.recvfrom(ETH_P_SIZE)

        eth_len = 14
        eth_header = packet[:eth_len]

        ether = struct.unpack('!6s6sH', eth_header)

        packet_type = ether[2]

        # compute the frequency for each known host
        elapsedExec = dt.now() - lastExec
        if elapsedExec.total_seconds() >= 5:
            updatePktFrequency()

        if isIP(packet_type):
            print('is IP')
            ip_unpack = struct.unpack(
                '!BBHHHBBH4s4s', packet[eth_len:20+eth_len])

            ip_options = packet[20+eth_len:]
            ip_source = socket.inet_ntoa(ip_unpack[8])
            ip_dest = socket.inet_ntoa(ip_unpack[9])  # * this is me!

            ip_options_type = ip_options[0]
            ip_options_code = ip_options[1]

            ip_protocol = ip_unpack[6]
            print('ip proto', ip_protocol)

            if ip_protocol == IP_PROTO_ICMP:
                if isIcmpReq(ip_options_type, ip_options_code):
                    print('icmp req')
                    addFoundIPAndCalcFreq(ip_source)
                    print('ip dict', ip_dictionary)

        lastExec = dt.now()
        print('\n')
