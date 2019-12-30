# Logscan
Building a script to Scan logs from embedded devices looking for IP addresses, that they might be connecting to.
It will open every single .txt file located in the same folder as read.py

## Requirements:
1- Install any Python distribution from: https://www.python.org/downloads/


## To Execute:
1. Create a new folder and add there all files to be inspected
2. Change all your files extensions to .txt
3. Save "read.py" into your new folder with all .txt files. 
4. Install Python, create a new Virtual Environment as described at: https://github.com/essvega/Python-Virtual-Environment/blob/master/Virtual%20Environment.md and install all packages described in requirements.txt
5. Activate your Virtual Environment 
6. Later, locate your file using your Terminal and execute:
         ***python read.py***

### To Do:  
  * Show all these API addresses in a well conformed GUI with their descriptions.
  * Convert .py file in an executable .exe


### Done: 
  * Exclude from filtering Private IP addresses
  * Exclude Bogon Ranges used in Local Networks without access to the public Internet
  * Include IPv6 to be analyzed
  * Request information from an API (Geolocation of IP addresses) about the IPs found.
