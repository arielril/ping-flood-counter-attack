from datetime import datetime as dt
import socket
import sys
import struct
import math

# DEFS
ETH_P_ALL = 0x0003
ETH_P_SIZE = 65536
ETH_P_IP = 0x0800
IP_PROTO_ICMP = 1


# info inside ip_dictionary
# * lastPacketAt = time of the last packet received
# * pktIntervalSec = interval of packets receive in seconds
# * attackPktsCount = quantity of packets that was lower than the threshold setup to consider as an attack
ip_dictionary = dict({})


def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)


def addFoundIP(ip: str) -> bool:
    if ip not in ip_dictionary.keys():
        ip_dictionary[ip] = dict({
            'pktIntervalSec': math.inf,
            'attackPktsCount': 0,
        })
        return True
    return False


def receivePacket(ip: str):
    now = dt.now()
    if 'lastPacketAt' not in ip_dictionary[ip].keys():
        ip_dictionary[ip]['lastPacketAt'] = now
        return

    packet_inteval_dt = now - ip_dictionary[ip]['lastPacketAt']
    ip_dictionary[ip]['pktIntervalSec'] = packet_inteval_dt.total_seconds()
    ip_dictionary[ip]['lastPacketAt'] = now


def getPacketInterval(ip: str) -> float:
    if 'pktIntervalSec' not in ip_dictionary[ip].keys():
        ip_dictionary[ip]['pktIntervalSec'] = math.inf
    return ip_dictionary[ip]['pktIntervalSec']


def isPingFloodAttack(ip: str, interval: float) -> bool:
    # TODO consider an IP source that sends some "attack packets" and then send a normal pkt (intermittent)

    ATTACK_PKTCOUNT_THRESHOLD = 10
    ATTACK_PKTINTERVAL_THRESHOLD = 0.1

    # if the property was not initialized, initialize
    if 'attackPktsCount' not in ip_dictionary[ip].keys():
        ip_dictionary[ip]['attackPktsCount'] = 0
        return False

    # if the interval of the packets is less than the threshold, then is an attack
    if interval < ATTACK_PKTINTERVAL_THRESHOLD:
        ip_dictionary[ip]['attackPktsCount'] += 1

    # if the source overlaps the max attack pkt count, counter attack
    if ip_dictionary[ip]['attackPktsCount'] >= ATTACK_PKTCOUNT_THRESHOLD:
        return True

    return False


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


def printInfo():
    for ip in ip_dictionary.keys():
        pktInterval = 0
        lastPacketAt = 0
        attackPktsCount = 0
        if 'pktIntervalSec' in ip_dictionary[ip].keys():
            pktInterval = ip_dictionary[ip]['pktIntervalSec']
        if 'lastPacketAt' in ip_dictionary[ip].keys():
            lastPacketAt = ip_dictionary[ip]['lastPacketAt']
        if 'attackPktsCount' in ip_dictionary[ip].keys():
            attackPktsCount = ip_dictionary[ip]['attackPktsCount']
        print('IP:', ip, '\tPkt Interval:',
              pktInterval, '\tLastPktAt:', lastPacketAt,
              '\tAttackPkts:', attackPktsCount)


if __name__ == "__main__":
    sock = getSocket('eth0')

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
                    # add the ip in the botnet list
                    if addFoundIP(ip_source):
                        print('MAC:', bytes_to_mac(ether[1]))
                        print('IP:', ip_source)

                    # set the packet as received
                    receivePacket(ip_source)
                    # get the interval (s) between the received packets
                    pInterval = getPacketInterval(ip_source)

                    if isPingFloodAttack(ip_source, pInterval):
                        # TODO counter attack
                        print('getting attacked!!!')
                        printInfo()
                        sys.exit()

            printInfo()
