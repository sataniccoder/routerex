#!/usr/bin/env python3
from colorama import Fore, Back, Style
import socket
import subprocess
import os
from scapy.all import *
def main():
    try:
        default_range = "192.168.0.1/24"
        while True:
            os.system("clear")
            print(Fore.GREEN)
            print('''
                ___    ___            __   _
               / __|  / __|    /\    |  \ | | 
               \ \   | |      /__\   |   \| | 
             __/ /   | |__   / __ \  | |\   |
            |___/     \___| /_/  \_\ |_| \__|

        --------------------------------------------

        1) scapy scan default_range (loud but fast)
        2) scapy scan custome range (same as above)
        3) port scan a target ip
        4) scan all default_range and ports (very long)

        --------------------------------------------
            ''')
            print(Style.RESET_ALL)           
            cho = int(input("[#] enter choice : "))
            os.system("clear")
            if cho == 1:
                print("[#] time : 5+ seconds")  
                print("[#] running...")

                target_ip = default_range
                arp = ARP(pdst=target_ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp

                result = srp(packet, timeout=3, verbose=0)[0]
                clients = []

                for sent, received in result:
                    clients.append({'ip': received.psrc, 'mac': received.hwsrc})
                print(Fore.YELLOW)
                print("\n\n-------------------------------------")
                print("available devices in the network:")
                print("")
                print("IP" + " "*18+"MAC")
                for client in clients:
                    print("{:16}    {}".format(client['ip'], client['mac']))
                print("\n-------------------------------------")
                print(Style.RESET_ALL)
                print("\n\n\n")
            if cho == 2:
                print("[#] time : 5+ seconds")  
                print("[#] running...")

                target_ip = input("eg: xxx.xxx.xxx./24 \netner range : ")
                arp = ARP(pdst=target_ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp

                result = srp(packet, timeout=3, verbose=0)[0]
                clients = []

                for sent, received in result:
                    clients.append({'ip': received.psrc, 'mac': received.hwsrc})
                print(Fore.YELLOW)
                print("\n\n-------------------------------------")
                print("available devices in the network:")
                print("")
                print("IP" + " "*18+"MAC")
                for client in clients:
                    print("{:16}    {}".format(client['ip'], client['mac']))
                print("\n-------------------------------------")
                print(Style.RESET_ALL)
                print("\n\n\n")
            if cho == 3:
                def scan_ip(ip, min_port, max_port):
                    while min_port != max_port:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        try:
                            s.connect((ip, min_port))
                            print(min_port)
                        except Exception:
                            pass
                        s.close()
                        min_port = min_port + 1
                def xmas_scan(ip, min_port, max_port):
                    sport = RandShort()
                    while min_port != max_port:
                        pkt = sr1(IP(dst=ip)/TCP(sport=sport, dport=min_port, flags="FPU"), timeout=1, verbose=0)
                        if pkt != None:
                                if pkt.haslayer(TCP):
                                        if pkt[TCP].flags == 20:
                                            pass
                                        else:
                                            print("[port] ", min_port, "TCP flag")
                                elif pkt.haslayer(ICMP):
                                    print("[port] ", min_port, "ICMP resp / filtered")
                                else:
                                    pass
                        else:
                            print("[port] ", min_port ,"Open / filtered")
                        min_port = min_port + 1

                def udp_scan(ip, min_port, max_port):
                    while min_port != max_port:
                        pkt = sr1(IP(dst=ip)/UDP(sport=port, dport=min_port), timeout=2, verbose=0)
                        if pkt == None:
                            pass
                            #print("[port] ", min_port, "Open / filtered")
                        else:
                            if pkt.haslayer(ICMP):
                                pass
                            elif pkt.haslayer(UDP):
                                print("[port] ", min_port, "Open / filtered")
                            else:
                                pass
                        min_port = min_port + 1
                ip = input("[#] enter ip : ")
                min_port = int(input("[#] enter min port : "))
                min_p = min_port
                max_port =int(input("[#] enter max port : "))
                basic = input("\ny = all \nn = only basic scan\n[#] go thourgh all scans [y/n] ")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    print("[#] press CTRL+C to skip scan")
                    try:
                        print(Fore.YELLOW)
                        print("[#] scanning...")
                        print("----------------------\n")
                        scan_ip(ip, min_port, max_port)
                        min_port = min_p
                        print("\n----------------------")
                        print(Style.RESET_ALL)
                        print("\n\n")
                    except KeyboardInterrupt:
                        print("[#] skipping")
                    if basic == "y" or "Y":
                        chek = input("[#] run udp scan (it can take a while) [y/n] ")
                        if chek == "y":
                            try:
                                print("[#] running udp scan...")
                                print(Fore.YELLOW)
                                print("\n----------------------\n")
                                udp_scan(ip, min_port, max_port)
                                print("\n----------------------\n")
                                print(Style.RESET_ALL)
                                print("[#] done udp scan!")
                            except  KeyboardInterrupt:
                                print("\n----------------------\n")
                                print(Style.RESET_ALL)
                                print("[#] skipping")
                        elif chek == "n":
                            pass
                        else:
                            pass
                        print("\n\n\n")
                        print("\n\n")
                        try:
                            print("[#] running Xmas scan...")
                            print(Fore.YELLOW)
                            print("\n----------------------\n")
                            min_port = min_p
                            xmas_scan(ip, min_port, max_port)
                            print("\n----------------------\n")
                            print(Style.RESET_ALL)
                            print("[#] Xmas scan done!")
                        except KeyboardInterrupt:
                            print("\n----------------------\n")
                            print("[#] skipping")
                    else:
                        pass
                    print("[#] done!")
            if cho == 4:
                def scan_ip(ip, min_port, max_port):
                    while min_port != max_port:
                        min_port = m
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        try:
                            s.connect((ip, min_port))
                            print(min_port)
                        except Exception:
                            pass
                        s.close()
                        min_port = min_port + 1
                min_port = int(input("[#] enter min port : "))
                max_port = int(input("[#] enter max port : "))
                m = min_port
                print("[#] time : fucking long")  
                print("[#] running...\n")

                target_ip = default_range
                arp = ARP(pdst=target_ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                #print("ree")
                result = srp(packet, timeout=3, verbose=0)[0]

                for sent, received in result:
                    ip = received.psrc
                    print("IP ", ip)
                    print("--------[PORTS]--------")
                    print(Fore.YELLOW)
                    scan_ip(ip, min_port, max_port)
                    print(Style.RESET_ALL)
                    print("-----------------------")
                    print("\n\n\n\n")
                    
                    
                        
            else:
                pass

    except KeyboardInterrupt:
        print("[!]")
