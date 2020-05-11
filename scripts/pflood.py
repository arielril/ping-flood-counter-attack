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

ip_dictionary = dict({})


def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)


def computeFrequency(ip: str) -> float:
    pktCount = ip_dictionary[ip]['pktCount']
    elapsedOcc = (dt.now() - ip_dictionary[ip]['lastOcc']).total_seconds()

    # compute the frequency with packet per second
    return pktCount / elapsedOcc


def addFoundIP(ip: str) -> bool:
    if ip not in ip_dictionary.keys():
        ip_dictionary[ip] = dict({
            'pktCount': 0,
        })
        return True
    return False


def incrementReceivedPackets(ip: str):
    # create the property
    if 'pktCount' not in ip_dictionary[ip].keys():
        ip_dictionary[ip]['pktCount'] = 0

    # increment pktCount
    ip_dictionary[ip]['pktCount'] += 1

    # if it is the first packet, set the occurrence time
    if ip_dictionary[ip]['pktCount'] == 1:
        ip_dictionary[ip]['lastOcc'] = dt.now()
        print('pkt one', ip_dictionary[ip]['lastOcc'])

    # if the pktCount passes the threshold, compute frequency and clear pktCount
    if ip_dictionary[ip]['pktCount'] > 2:
        updatePktFrequency(ip)
        ip_dictionary[ip]['pktCount'] = 0


def updatePktFrequency(ip: str):
    ip_dictionary[ip]['frequency'] = computeFrequency(ip)


def updateAllPktFrequency():
    for ip in ip_dictionary.keys():
        updatePktFrequency(ip)


def cleanAllPacketCount():
    for ip in ip_dictionary.keys():
        ip_dictionary[ip]['pktCount'] = 0


def getSocket(if_net: str) -> socket:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('failed to create socket', str(msg))
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


def printIPFreq():
    for ip in ip_dictionary.keys():
        freq = 0
        pktCount = 0
        if 'frequency' in ip_dictionary[ip].keys():
            freq = ip_dictionary[ip]['frequency']
        if 'pktCount' in ip_dictionary[ip].keys():
            pktCount = ip_dictionary[ip]['pktCount']
        print('IP:', ip, '\tFreq:', freq, '\tCount:', pktCount)


if __name__ == "__main__":
    sock = getSocket('eth0')

    lastExec = dt.now()

    while True:
        (packet, addr) = sock.recvfrom(ETH_P_SIZE)

        eth_len = 14
        eth_header = packet[:eth_len]

        ether = struct.unpack('!6s6sH', eth_header)

        packet_type = ether[2]

        if isIP(packet_type):
            ip_unpack = struct.unpack(
                '!BBHHHBBH4s4s', packet[eth_len:20+eth_len])

            ip_options = packet[20+eth_len:]
            ip_source = socket.inet_ntoa(ip_unpack[8])
            ip_dest = socket.inet_ntoa(ip_unpack[9])  # * this is me!

            # protocol encapsulated inside the IP
            ip_protocol = ip_unpack[6]
            # options for the encapsulated protocol
            ip_options_type = ip_options[0]
            ip_options_code = ip_options[1]

            if ip_protocol == IP_PROTO_ICMP:
                print('ping')
                if isIcmpReq(ip_options_type, ip_options_code):
                    """
                        When receiving an ICMP Request (ping) we have to save the source 
                        machines to use to counter attack the attacker that is using 
                        ping flood.
                        While receiving valid icmp requests is needed to compute the 
                        frequency of the ping execution from the ip_source to check if the 
                        source isn't executing a ping flood attack.
                        If the ip_source is attacking the home machine, we need to counter attack!
                    """
                    if addFoundIP(ip_source):
                        print('MAC:', bytes_to_mac(ether[1]))
                        print('IP:', ip_source)

                    incrementReceivedPackets(ip_source)

            printIPFreq()

        # print('\n')
