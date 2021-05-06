import os

'''
apt = ["hostapd","aircrack-ng","systemctl","tor","wdget"]
for x in apt:
    command = "apt-get install "+x
    os.system(command)
print("[#] done!")
print("[#] adding lunch command")
path = "/bin/bash"
#'''

dir_path = os.path.dirname(os.path.realpath(__file__))
x = '''
#!/bin/bash

cmd="python3 '''+dir_path+'''/routerex.py"
echo $cmd
$cmd
'''
f = open("/usr/local/bin/routerex","x+")
f.write(x)
f.close()
os.system("chmod +x /usr/local/bin/routerex")
print("[#] done!")
print("[#] custome command: routerex")
