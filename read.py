import re
list = []

with open('log.txt') as f:
    for line in f:
        ip = re.findall( r'[1-2]{0,1}[0-6][8]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}', line)
        if len(ip) > 0 :
            print(ip)