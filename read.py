import re
list = ["0"]
print("Starting ... \nPlease do not close this window until we finish")



with open('log.txt') as f:
    for line in f:
        ip = re.findall( r'[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}', line)
        if len(ip) > 0 :
            for a in list:
                if not ip in list:
                    list.append(ip)

for i in list:
    print(i)
print("                         ")
print("                         ")
print("                         ")
print("*************************")
print("*                       *")
print("* Powered by @Essiel V. *")
print("*                       *")
print("*************************")
