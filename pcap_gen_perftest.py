# !/usr/bin/python

import sys
import binascii
import random
import copy
import argparse
import textwrap
import scapy
from scapy.all import *

# Global header for pcap 2.4
pcap_global_header = ('D4 C3 B2 A1'
                      '02 00'  # File format major revision (i.e. pcap <2>.4)  
                      '04 00'  # File format minor revision (i.e. pcap 2.<4>)   
                      '00 00 00 00'
                      '00 00 00 00'
                      'FF FF 00 00'
                      '01 00 00 00')

# pcap packet header that must preface every packet
pcap_packet_header = ('AA 77 9F 47'
                      '90 A2 04 00'
                      'XX XX XX XX'  # Frame Size (little endian) 
                      'YY YY YY YY')  # Frame Size (little endian)

eth_header = ('00 E0 4C 00 00 01'  # Dest Mac    
              '00 04 0B 00 00 02'  # Src Mac  
              '08 00')  # Protocol (0x0800 = IP)

ip_header = ('45'  # IP version and header length (multiples of 4 bytes)   
             '00'
             'XX XX'  # Length - will be calculated and replaced later
             '00 00'
             '40 00 40'
             '11'  # Protocol (0x11 = UDP)          
             'YY YY'  # Checksum - will be calculated and replaced later      
             '0A 00 00 01'  # Source IP (Default: 10.0.0.1)
             '0A 00 00 02')  # Dest IP (Default: 10.0.0.2)

udp_header = ('ZZ ZZ'  # TODO                   
              'XX XX'  # Port - will be replaced later                   
              'YY YY'  # Length - will be calculated and replaced later        
              '00 00')

packet_sizes = (64,)  # ,                     #PCAP file will be generated for these


# 128,                    #packet sizes
# 256,
# 512,
# 1024,
# 1280,
# 1500)


def getByteLength(str1):
    return len(''.join(str1.split())) / 2


def writeByteStringToFile(bytestring, filename):
    bytelist = bytestring.split()
    bytes = binascii.a2b_hex(''.join(bytelist))
    bitout = open(filename, 'ab')
    bitout.write(bytes)


def backspace(n):
    # print((b'\x08' * n).decode(), end='') # use \x08 char to go back
    sys.stdout.write('\r' * n)  # use '\r' to go back


def calculateRemainingPercentage(current, n):
    #     print("%d - %d" % (current,n))
    percent = str("all-byte packets: %d%%" % (int((current / float(n)) * 100)))
    sys.stdout.write(percent)

    backspace(len(percent))  # back for n chars


#     return ((current/n) * 100)

def negate_bit(bit):
    if bit == "1":
        return "0"
    return "1"


def generatePCAPScapy(pcapfile, n, packet_size):

    packets = dict(list())
    for pktSize in packet_size:
        packets[pktSize] = list()

    for i in range(0, n):
        sport = getRandomPort()
        dport = getRandomPort()
        src_ip = getRandomIP_normal()
        dst_ip = getRandomIP_normal()
        src_mac = getRandomMAC_normal()
        dst_mac = getRandomMAC_normal()

        calculateRemainingPercentage(i, n)

        for pktSize in packet_size:
            p = Ether(dst=dst_mac, src=src_mac) / IP(dst=dst_ip, src=src_ip) / UDP(sport=sport, dport=dport)
            s = "\x00" * (pktSize - len(p) - 4)
            p = p / Raw(s)
            packets[pktSize].append(p)


    for pktSize in packets:
        output = pcapfile+str(".{}bytes.pcap".format(pktSize))
        wrpcap(output,packets[pktSize])


def generatePCAPHEX(pcapfile, n, packet_sizes):

    for i in range(0, n):
        sport = getRandomPort()
        dport = getRandomPort()
        src_ip = getRandomIP()
        dst_ip = getRandomIP()
        src_mac = getRandomMAC()
        dst_mac = getRandomMAC()

        calculateRemainingPercentage(i, n)

        # first we put one package into the file whose destination port number is $dp
        # update ethernet header
        eth_header = dst_mac + ' ' + src_mac + "0800"
        # update ip header
        ip_header = ('45'
                     '00'
                     'XX XX'
                     '00 00'
                     '40 00 40'
                     '11'
                     'YY YY')
        ip_header += src_ip
        ip_header += dst_ip

        udp = udp_header.replace('XX XX', "%04x" % dport)

        udp = udp.replace('ZZ ZZ', "%04x" % sport)

        for pktSize in packet_sizes:
            message = getMessage(pktSize)

            udp_len = getByteLength(message) + getByteLength(udp_header)
            udp = udp.replace('YY YY', "%04x" % udp_len)

            ip_len = udp_len + getByteLength(ip_header)
            ip = ip_header.replace('XX XX', "%04x" % ip_len)
            checksum = ip_checksum(ip.replace('YY YY', '00 00'))
            ip = ip.replace('YY YY', "%04x" % checksum)

            pcap_len = ip_len + getByteLength(eth_header)
            hex_str = "%08x" % pcap_len
            reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
            pcaph = pcap_packet_header.replace('XX XX XX XX', reverse_hex_str)
            pcaph = pcaph.replace('YY YY YY YY', reverse_hex_str)

            if i == 0:
                bytestring = pcap_global_header + pcaph + eth_header + ip + udp + message

            else:
                bytestring = pcaph + eth_header + ip + udp + message

            writeByteStringToFile(bytestring, pcapfile + str(".%dbytes.pcap" % pktSize))


def splitN(str1, n):
    return [str1[start:start + n] for start in range(0, len(str1), n)]


# Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):
    # split into bytes
    words = splitN(''.join(iph.split()), 4)

    csum = 0
    for word in words:
        csum += int(word, base=16)

    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF

    return csum


def getMac(mac):
    # get some random number between 1-255 for the first part of MAC (first 2 byte)
    # first_2byte=random.randrange(1,255)
    mac = str("%06x" % (mac))
    # print(mac)
    return mac


def getRandomMAC():
    return "00" + str("%0.10X" % random.randint(1, 0xffffffffff))

def getRandomMAC_normal():
    return "00:" + str("%0.2X:%0.2X:%0.2X:%0.2X:%0.2X" % (random.randint(1,0xff),random.randint(1,0xff),random.randint(1,0xff),random.randint(1,0xff),random.randint(1,0xff)))

def getRandomIP():
    return str("%0.8X" % random.randint(1, 0xffffffff))

def getRandomIP_normal():
    ip = str("{}.{}.{}.{}".format((random.randint(1,255)), (random.randint(1,255)), (random.randint(1,255)), (random.randint(1,255))))
    # print ip
    return ip


# this function gets a random vlan id in the specified range starting from 101
def getVLANid(spec_range):
    start = 100
    return random.randint(start + 1, start + spec_range)


def getNextIP(nextIP, ul_dl):
    if (nextIP % 256) == 0:
        nextIP += 1
    if ul_dl:
        s_pre = "0A"
    else:
        s_pre = "AA"

    s = s_pre + str("%0.6X" % nextIP)

    return s


def getRandomPort():
    port = random.randint(1, 65535)
    if (port == 4305):
        getRandomPort()
    return int(port)


def parseMAC(mac):
    ret_val = mac.replace(":", "").upper()
    if len(ret_val) != 12:  # check mac address length
        print "ERROR during parsing mac address - not long enough!: {}".format(mac)
        exit(-1)
    return ret_val


def add_payload(p, pkt_size):
    if len(p) < pkt_size:
        #"\x00" is a single zero byte
        s = "\x00" * (pkt_size - len(p))
        p = p / Raw(s)
    return p


def parseIP(ip):
    ret_val = ""
    # split IP address into 4 8-bit values
    ip_segments = ip.split(".")
    for i in ip_segments:
        ret_val += str("%0.2X" % int(i))
    if len(ret_val) != 8:  # check length of IP
        print "ERROR during parsing IP address - not long enough!: {}".format(ip)
        exit(-1)
    return ret_val


def writeoutLine(filename, line):
    file = open(filename, 'a')
    file.write(line + "\n")
    file.close()


def getMessage(packetsize):
    message = ''
    for i in range(0, int(packetsize) - 46):  # 46 = eth + ip + udp header
        message += "%0.2X " % random.randint(0, 255)

    return message


"""------------------------------------------"""
""" End of functions, execution starts here: """
"""------------------------------------------"""

parser = argparse.ArgumentParser(description="Usage of PCAP generator performance tester",
                                 usage="python pcap_gen_perftest.py -b <backend> -o <OUTPUT> [-n <#flows>  -s <PACKETSIZE>]",
                                 formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-b', '--backend', nargs=1,
                    help=textwrap.dedent('''\
                         Specify the backend.
                         \033[1mSCAPY\033[0m will use scapy library to craft the packets and write out the pcap file
                         \033[1mHEX\033[0m will create the pcaps by writing HEX strings/numbers into the file directly'''),
                    required=True)
parser.add_argument('-o', '--output', nargs=1,
                    help="Specify the output PCAP file's basename! "
                         "Output will be [output].[PACKETSIZE]bytes.pcap extension is not needed!",
                    required=True)
parser.add_argument('-s','--packetsizes',nargs=1,
                    help="Specify here the required packetsize! "
                    "In case of more than one, just create a comma separated list "
                    "such as 64,112,42. Default: 64",
                    required=False,
                    default=[64])
parser.add_argument('-n', '--num', nargs=1,
                    help="Specify the number of flows to create - Default: 100",
                    required=False,
                    default=["100"])

args = parser.parse_args()

backend = args.backend[0]
backends = ['SCAPY', 'HEX']

output = args.output[0]
num = int(args.num[0])

packet_sizes = (args.packetsizes[0]).split(',')
packet_sizes = list(map(int, packet_sizes))

if backend not in backends:
    print "Backend has not set properly (SCAPY, HEX)"
    exit - 1


for i in packet_sizes:
    open(str("%s.%dbytes.pcap" % (output, int(i))), 'w')  # delete contents


if backend == "HEX":
    generatePCAPHEX(output, num, packet_sizes)
else:
    generatePCAPScapy(output, num, packet_sizes)

