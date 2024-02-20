# Network Credential Probe

Automated credential stuffing attack and script propagation on a network using Python Scapy library. Mimics Mirai botnet.
  
<p>A list of passwords is provided along with a username and a file containing a list of IP addresses. Or choose a local scan for all network interfaces and all /24 addresses. Hosts are scanned to see if they are reachable with an ICMP request. Reachable hosts undergo a TCP SYN scan to find accessible ports.</p>

1. If port 22 is open, attempt to brute-force SSH using Python Paramiko library. 
2. If port 23 is open, attempt to brute-force Telnet using Python Telnetlib library. 
3. If ports 80, 8080, or 8888 are open, attempt to brute-force web login using Python requests library using a GET request to detect a website and a POST request.

If any of these are successful an alert is printed to the console with the successful username and password, port, and IP address.

For successful Telnet or SSH access in situations 1) and 2): A file can optionally be deployed on the target host. Also optionally, this script can self-propagate by placing the net_attack.py and password files on the target host. 


### Usage

`./net_attack.py [[-t <IPs_filename>] or [-L]] -p <port numbers> -u <username> -f <Passwords_filename> [-d <Script_filename>] [-P]`

Example: `./net_attack.py -t ip_list.txt -p 22,23,25,80 -u root -f passwords.txt` 

Example: `./net_attack.py -L -p 80,123,24738,8080,8888 -u admin -f pw.txt -d other.sh`

Example: `./net_attack.py -L -p 22,23 -u root -f passwords.txt -P`

<br>

**IP Addresses File**

`-t <filename>`

File containing IP addresses separated by newlines.

**Ports**

`-p <ports>`

Ports to scan on each host. Can be separated by commas. Each port will undergo a TCP SYN scan.

**Username**

`-u <username>`

User must provide a username to try during credential stuffing.

**Passwords File**

`-f <filename>`

File containing a list of passwords separated by newlines.

**[OPTIONAL] Deploy File**

`-d <filename>`

The filename to be deployed on the target host after a successful Telnet or SSH connection. 

**[OPTIONAL] Self Propagate**

`-P`

Self-propagation mode drops 'net_attack.py' and the passwords file on the target host after a successful Telnet or SSH connection. 

**[OPTIONAL] Local Scan Mode**

`-L`

Scan all IP addresses on all network interfaces (assuming a /24 network) instead of using a file with a list of IP addresses. `-f <filename>` cannot be used with this option. `-P` and `-L` can be used together. 
