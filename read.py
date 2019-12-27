import re
import os
import requests
import json
import ipinfo
from IPy import IP

#Request token for every indivual that tries to use this script. They must use their own token code
access_token = input('Enter your token access:  ')
handler = ipinfo.getHandler(access_token)

list = ["0"]
orderedlist = []
latest = []
print("Starting ... \nPlease do not close this window until we finish")

#It saves all IP addresses found while running openfor()
def organize():
    for j in list:
        for k in j:
            orderedlist.append(k)

#It reduces the table to unique values. It will remove any IP address repeated
def removing():
    for z in orderedlist:
        if z not in latest:
            latest.append(z)
          
#From the previous list holding only unique values, this function will 
#remove all IP addresses that are not recognized as PUBLIC
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

#It opens every .txt file targeted
def openfor():
    with open(dirname + '.txt') as f:
        for line in f:
            ip = re.findall( r'[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}', line)
            if len(ip) > 0 :
                for a in list:
                    if not ip in list:
                        list.append(ip)

#It opens all .txt files concentrated in the same folder
dir_path = os.path.dirname(os.path.realpath(__file__))
for file in os.listdir(dir_path):
    if file.endswith(".txt"):
        dirname = os.path.splitext(file)[0]
        print("*"*100)
        print(dirname)
        print("-"*100)
        print("-"*100)
        print(" "*100)
        print(" "*100)
        print(" "*100)
        print(" "*100)
        
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


