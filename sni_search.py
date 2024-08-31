from scapy.all import *
from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName

# filter = "ip dst 130.255.77.28"
filter = "net 0.0.0.0/0"

interface = "eth0"

def packet_callback(packet):
    if packet.haslayer(TLS):
        if packet[TLS].type == 22: #указывает на хэндшейк
            if packet['TLS'].msg[0].msgtype == 1: #указывает на ClienHello
        # print("Client Hello packet captured:")
        # packet[TLS_Ext_ServerName].show()
                print(f'SNI == {packet[TLS_Ext_ServerName].servernames[0].servername.decode()}')

sniff(prn=packet_callback, filter=filter,iface=interface, store=0)