from netfilterqueue import NetfilterQueue as nfq
from scapy.all import *
import signal

def signal_handler(sig, frame):
    print('Завершение программы.')
    exit(0)

def packet_listener(packet):
  scapy_packet = IP(packet.get_payload())
  if scapy_packet.haslayer('ICMP'):
    print(scapy_packet[IP].show())
    scapy_packet['IP'].src = '10.10.10.10'
    del scapy_packet[IP].chksum
    packet.set_payload(bytes(scapy_packet))
    print(scapy_packet[IP].show())
    packet.accept()


if __name__ == "__main__":

    try:
        print('Приложение запущено. Нажмите Ctrl+C для завершения.')
        queue = nfq()
        queue.bind(1, packet_listener)
        queue.run()

    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, signal_handler)