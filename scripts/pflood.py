from datetime import datetime as dt
import socket
import sys
import struct
import math
import os

# DEFS
ETH_P_ALL = 0x0003
ETH_P_SIZE = 65536
ETH_P_IP = 0x0800
IP_PROTO_ICMP = 1


# info inside ip_dictionary
# * lastPacketAt = time of the last packet received
# * pktIntervalSec = interval of packets receive in seconds
# * attackPktsCount = quantity of packets that was lower than the threshold setup to consider as an attack
# * MAC = the MAC address to send a ping request (the router MAC)
ip_dictionary = dict({})


def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)


def addFoundIP(ip: str, mac: str = '') -> bool:
    if ip not in ip_dictionary.keys():
        ip_dictionary[ip] = dict({
            'pktIntervalSec': math.inf,
            'attackPktsCount': 0,
            'MAC': mac,
        })
        print('MAC:', bytes_to_mac(ether[1]))
        print('IP:', ip_source)
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


def getSocket(if_net: str, proto: int = socket.ntohs(ETH_P_ALL)) -> socket:
    try:
        s = None

        if proto == socket.getprotobyname('icmp'):
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              proto)
            print('icmp socket created!')
        else:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              proto)
            print('eht socket created!')
    except OSError as msg:
        print('failed to create socket', str(msg))
        sys.exit(1)

    if proto == socket.getprotobyname('icmp'):
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    else:
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
        mac = ''
        if 'pktIntervalSec' in ip_dictionary[ip].keys():
            pktInterval = ip_dictionary[ip]['pktIntervalSec']
        if 'lastPacketAt' in ip_dictionary[ip].keys():
            lastPacketAt = ip_dictionary[ip]['lastPacketAt']
        if 'attackPktsCount' in ip_dictionary[ip].keys():
            attackPktsCount = ip_dictionary[ip]['attackPktsCount']
        if 'MAC' in ip_dictionary[ip].keys():
            mac = ip_dictionary[ip]['MAC']
        print('IP:', ip,
              '\tMAC', mac,
              '\tPkt Interval:', pktInterval,
              '\tLastPktAt:', lastPacketAt,
              '\tAttackPkts:', attackPktsCount)


# ################################################################################
# Send ping area

def getChecksum(msg: bytes) -> int:
    s = 0
    msg = (msg + b'\x00') if len(msg) % 2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)


def getIcmpRequestHeader():
    header = dict({
        'type': 8,
        'code': 0,
        'checksum': 0,
        'id': 12345,
        'seqnumber': 0,
        'payload': bytes('ª{!"#$%&\'()*+,-./01234567', 'utf8'),
    })
    return header


def getIcmpPacket() -> bytes:
    icmp_header_props = getIcmpRequestHeader()
    icmp_h = struct.pack(
        '!BBHHH',
        icmp_header_props['type'],
        icmp_header_props['code'],
        icmp_header_props['checksum'],
        icmp_header_props['id'],
        icmp_header_props['seqnumber'],
    )

    padBytes = []
    startVal = 0x42
    for i in range(startVal, startVal + 55):
        padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
    data = bytes(padBytes)

    checksum = getChecksum(icmp_h + data)

    icmp_h = struct.pack(
        '!BBHHH',
        icmp_header_props['type'],
        icmp_header_props['code'],
        checksum,
        icmp_header_props['id'],
        icmp_header_props['seqnumber'],
    )
    icmp_pkt = icmp_h + data

    return icmp_pkt


def getIPPacket(ip_source: str, ip_dest: str) -> bytes:
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_total_len = 0
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_ICMP
    ip_check = 0
    ip_saddr = socket.inet_aton(ip_source)
    ip_daddr = socket.inet_aton(ip_dest)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_h = struct.pack(
        '!BBHHHBBH4s4s',
        ip_ihl_ver,
        ip_tos,
        ip_total_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        ip_saddr,
        ip_daddr,
    )

    return ip_h


def sendPing(s: socket.socket, ip_source: str, ip_dest: str):
    icmp_pkt = getIcmpPacket()
    ip_h = getIPPacket(ip_source, ip_dest)

    dest_addr = socket.gethostbyname(ip_dest)
    s.sendto(ip_h + icmp_pkt, (dest_addr, 0))
    s.close()


# End of Send ping
# ################################################################################


if __name__ == "__main__":

    # for i in range(0, 10000):
    #     s = getSocket(None, socket.getprotobyname('icmp'))
    #     s1 = getSocket(None, socket.getprotobyname('icmp'))
    #     s2 = getSocket(None, socket.getprotobyname('icmp'))

    #     sendPing(s, '10.0.1.10', '10.0.0.10')
    #     sendPing(s1, '10.0.1.10', '10.0.3.10')
    #     sendPing(s2, '10.0.1.10', '10.0.4.10')

    # sys.exit()

    sock = getSocket('eth0')

    try:
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
                        addFoundIP(ip_source, bytes_to_mac(ether[1]))

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
    except KeyboardInterrupt:
        print('Done!')
