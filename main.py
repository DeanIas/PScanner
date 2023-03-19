import syn
from colorama import init,Fore,Style
import socket

init(autoreset=True)
ports = [20,    #FTP
         21,    #FTP
         22,    #SSH
         23,    #Telnet
         80,    #HTTP
         443,   #HTTPS
         8080,
         8443,
         53,    #DNS
         25,    #SMTP
         137,   #NetBios over tcp
         139,
         445,   #SMB
    ]
mylanip = syn.find_lan_ip()
print("[i] My LAN IP is :   ", mylanip)

host = input("Host: ")

try:
    socket.inet_aton(host)
    ip_addr = host
except socket.error:
    ip_addr = socket.gethostbyname(host)

for port in ports:
    packet = syn.SYNPacket(mylanip, ip_addr, port)
    sock = packet.socket()
    if packet.connect(sock):
        print(Style.BRIGHT + Fore.GREEN + f"[{ip_addr}]:{port} -> open" + Fore.RESET)
