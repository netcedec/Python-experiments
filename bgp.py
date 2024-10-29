from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP
from scapy.contrib.bgp import BGPHeader, BGPUpdate, BGPPathAttr, BGPNLRI_IPv4, BGPPALocalPref, BGPOpen

packets = rdpcap('bgp.pcap')
number = 0

for packet in packets:
    number+=1
    if packet.haslayer(TCP):
        if packet.haslayer(BGPHeader):
            if packet.haslayer(BGPOpen):
                print(f'\n\n\n PACKET NUMBER {number}')
                print(packet[BGPOpen].my_as)
                # print(packet[BGPUpdate].show())