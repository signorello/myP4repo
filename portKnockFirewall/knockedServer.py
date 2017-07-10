from scapy.all import *

sniff(iface="veth2", prn=lambda x: x.summary())
