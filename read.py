import re
import os
import requests
import json
import ipinfo
from IPy import IP

access_token = input('Enter your token access:  ')
handler = ipinfo.getHandler(access_token)

list = ["0"]
orderedlist = []
latest = []
print("Starting ... \nPlease do not close this window until we finish")


def organize():
    for j in list:
        for k in j:
            orderedlist.append(k)

def removing():
    for z in orderedlist:
        if z not in latest:
            latest.append(z)
          
def letsdoit():    
    for i in latest:
        ipe = IP(i)
        if ipe.iptype() == "PUBLIC":
            details = handler.getDetails(i)
            if 'org' in details.all:
               companies = details.org
            else:
               companies = "--NO DATA--"
            print("IP Address=> " + i + "; Country=> " + details.country_name + "; Region=> " + details.region + "; Company=> " + companies)

def openfor():
    with open(dirname + '.txt') as f:
        for line in f:
            ip = re.findall( r'[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}', line)
            if len(ip) > 0 :
                for a in list:
                    if not ip in list:
                        list.append(ip)

dir_path = os.path.dirname(os.path.realpath(__file__))
for file in os.listdir(dir_path):
    if file.endswith(".txt"):
        dirname = os.path.splitext(file)[0]
        print("*"*100)
        print(dirname)
        print("-"*100)
        print("-"*100)
        openfor()
        organize()
        removing()
        letsdoit()

print("                         ")
print("                         ")
print("*************************")
print("*                       *")
print("* Powered by @Essiel V. *")
print("*                       *")
print("*************************")


