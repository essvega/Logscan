# Logscan
Building a script to Scan logs from embedded devices looking for IP addresses, that they might be connecting to.

## Requirements:
1- Install any Python distribution from: https://www.python.org/downloads/


## To Execute:
1. Put your txt file with the name "log.txt" and file "read.py", both in the same folder. Then execute read.py through the Console (At        this time)
2. Later, locate your file using your Terminal and execute:
         ***python read.py***

### To Do:  
  * Show all these API addresses in a well conformed Front-end.


### Done: 
  * Exclude from filtering Private IP addresses
  * Exclude Bogon Ranges used in Local Networks without access to the public Internet
  * Include IPv6 to be analyzed
  * Request information from an API (Geolocation of IP addresses) about the IPs found.
