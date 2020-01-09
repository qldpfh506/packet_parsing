#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from scapy.all import *
from struct import *
from pcapfile import savefile
from binascii import hexlify

import re
import zlib
import geoip2.database
import os, subprocess
import optparse, zipfile, sys
import xml.etree.ElementTree as ET
import socket
import dpkt

from datetime import datetime

#ip로 바꿔주는 함수
def itoa(data):
    iplist = [(data>>24)&0xFF, (data>>16)&0xFF, (data>>8)&0xFF, data&0xFF]
    return ".".join("%d" % i for i in iplist)

#각 부분별 함수
def itop(data):
    return "TCP" if data == 6 else "UDP"

def parse_pattern(pcap_file, pattern):
    pattern_size = struct.calcsize(pattern)

    return struct.unpack(pattern, pcap_file.read(pattern_size))   

def parse_pcap_header(pcap_file):
    return parse_pattern(pcap_file, "=IIII")

def parse_ether_header(pcap_file):
    #packet data
    #ether_addr_octet[6]으로 표시되었기 때문에 pattern도 맞춰줌
    return parse_pattern(pcap_file, "!6B6BH")

def parse_ip_header(pcap_file):
    #pcap data
    #ip_frag_offset:5 은 바이트가 아닌 비트이기 때문에 8비트 합쳐서 1바이트로 취급
    return parse_pattern(pcap_file, "!BBHHBBBBHII")
    
def parse_udp_header(pcap_file):
    #packet data
    #처음 읽을 때 TCP가 아니라 UDP로 읽힘.
    #UDP면 포트번호 17, TCP면 포트번호가 6으로 표시됨.
    return parse_pattern(pcap_file, "!HHHH")
    
def parse_tcp_header(pcap_file):
    pass
    
data = './dl_test.pcap'
reader = geoip2.database.Reader('GeoLite2-City.mmdb')

pcap_file = open(data, "rb")

#global header
g_pattern = "=IHHIIII"
g_pattern_size = struct.calcsize(g_pattern)

gheader = pcap_file.read(g_pattern_size)

magic_num, v_major, v_minor, tz, flags, snaplen, network = struct.unpack(g_pattern, gheader)
#print(magic_num, v_major, v_minor, tz, flags, snaplen, network)

ts_sec, ts_usec, incl_len, orig_len = parse_pcap_header(pcap_file)

#print(datetime.fromtimestamp(ts_sec), ts_usec, incl_len, orig_len)

ether_data = parse_ether_header(pcap_file)
#print(ether_data[:6], ether_data[6:12], ether_data[12:])

ip_header, tos, total_length, ip_id, flags, offset, ttl, protocol, checksum, srcaddr, destaddr = parse_ip_header(pcap_file)

#protocol 구분
if protocol == 6:
    parse_tcp_header(pcap_file)
    pcap_file.read(length - 20)
    print(datetime.fromtimestamp(ts_sec),'.',ts_usec, "TCP", checksum, itoa(srcaddr),reader.city(itoa(srcaddr)).country.iso_code, '>', itoa(destaddr),reader.city(itoa(destaddr)).country.iso_code)

elif protocol == 17:
    sport, dport, length, checksum = parse_udp_header(pcap_file)
    pcap_file.read(length - 8)
    #print(sport, dport, length, checksum)
    print(datetime.fromtimestamp(ts_sec),'.',ts_usec, "UDP", itoa(srcaddr),reader.city(itoa(srcaddr)).country.iso_code, '>', itoa(destaddr),reader.city(itoa(destaddr)).country.iso_code)

#tcp_pattern = "!HHIIBBBBBBBBBBBHHH"
#tcp_pattern_size = struct.calcsize(tcp_pattern)

#tcp_header = pcap_file.read(tcp_pattern_size)
#source, dest, sequence, ack, ns, reserve, data, fin, syn, rst, psh, ack, urg, ecn, cwr, window,checksum, urgent_p = struct.unpack(tcp_pattern, tcp_header)

#print(source, dest, sequence, ack, ns, reserve, data, fin, syn, rst, psh, ack, urg, ecn, cwr, window,checksum, urgent_p)

