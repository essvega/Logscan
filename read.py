import re
private = ["192.168", "172.16", "10"]
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

def remoprivate():
    for z in latest:
        print("a")
        
        
def reducing(input_string, starting, ending):
    for i in latest:
        if (i.find(input_string, starting, ending) != -1):
            latest.remove(i)
        else:
            continue


with open('log.txt') as f:
    for line in f:
        ip = re.findall( r'[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}', line)
        if len(ip) > 0 :
            for a in list:
                if not ip in list:
                    list.append(ip)

        

organize()
removing()
reducing("0", 0, 1)
reducing("192.168.", 0, 8)
reducing("192.168", 0, 7)
reducing("8.8.8.8", 0, 24)
reducing("10.", 0, 3)
reducing("10", 0, 2)
reducing("172.16.", 0, 7)
reducing("172.16", 0, 6)


        
for i in latest:
    print(i)

print("                         ")
print("                         ")
print("*************************")
print("*                       *")
print("* Powered by @Essiel V. *")
print("*                       *")
print("*************************")
