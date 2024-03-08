from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
       ip_src = packet[IP].src
       ip_dst = packet[IP].dst
       protocol = packet[IP].proto
       print(f"IP Source: {ip_src} --> IP Destination: {ip_dst} | Protocol: {protocol}")

       if packet.haslayer(TCP):
          payload_TCP = packet[IP].payload
          print("TCP payload data : ")
          print(payload_TCP)

       if packet.haslayer(UDP):
          payload_UDP = packet[IP].payload
          print("UDPP payload data : ")
          print(payload_UDP)

      

print("sniffing started")
sniff(prn=packet_callback , store=0)  
