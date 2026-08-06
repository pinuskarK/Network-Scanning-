#!/user/bin/env python3
import subprocess 
import sys
 

print("\n=== SIMPLE NETWORK SCANNER ===")
print("This will fiding live devices and check for basic risks.\n")

#network range to enter
network = input("Enter your nework (example : 192.168.1.0/24): ")
print(f"\n[1] Scanning {network } for live devices...")

ping_cmd = f"nmap -sn{network} -oG - "
result = subprocess.run(ping_cmd,shell = True, capture_output = True ,text = True)

#Extract live IPs

live_ips = []
for line in result.stdout.split('\n'):
    if "status: Up" in line:
        # find IP between first ' (' and')'
        parts = line.split()
        for part in parts:
            if part.count('.') == 3 and part[0].isdigit():
                ip = part
                live_ips.append(ip)
                break


if not live_ips:
    print("No live hosts found. Check your network range .")
    #get own IP address from 'ip a'
    ip_cmd = "ip -4 addr show eth1 | awk '/inet / {print $2}' |cut -d/ -f1"
    own_ip = subprocess.run(ip_cmd,shell = True, capture_output =True, text=True).stdout.strip()


    if own_ip:
        live_ips.append(own_ip)
        print(f" -->Scanning own IP :{own_ip}")
    else:
        print("could not determine own IP.")
        sys.exit()



print(f"\n Fount{len(live_ips)}live IP(s):")
for ip in live_ips:
    print(f"  -{ip}")


print("\n[2] Quick prot scan +vulnerability hits...")
for ip in live_ips:
    print(f"\n--- scanning{ip} ---")

    #fast port scan

    port_cmd = f"nmap -F {ip}"
    port_result = subprocess.run(port_cmd,shell =True,capture_output = True,text =True)

    print(port_result.stdout)

    #simple vulnerability hits based on open ports

    output = port_result.stdout

    if "22/tcp" in port_result.stdout and "open" in output:
        print("  SSH port open (22).check if ssh version is old.")

    if "445/tcp" in port_result.stdout and "open" in output:
        print("  SMB port open (445).possible windows sharing risk.")
        
    if "80/tcp" in port_result.stdout and "open" in output:
        print("  Web server(80) detected.Check for default passwords.")

    if "21/tcp" in port_result.stdout and "open" in output:
        print("  FTP port open (21).Anonymous login possible.")


    if "3306/tcp" in port_result.stdout and "open" in output:
        print("  MySQLport (3306)open --check for weak passwerds.")


print("\n[3]Done! Check wireshark for captured packets.")        
    



