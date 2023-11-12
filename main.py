import syn
from colorama import init,Fore,Style
from tqdm import tqdm
from argparse import ArgumentParser
from ipaddress import IPv4Address
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
banner = r"""
__________  _________                                         
\______   \/   _____/ ____ _____    ____   ____   ___________ 
 |     ___/\_____  \_/ ___\\__  \  /    \ /    \_/ __ \_  __ \
 |    |    /        \  \___ / __ \|   |  \   |  \  ___/|  | \/
 |____|   /_______  /\___  >____  /___|  /___|  /\___  >__|   
                  \/     \/     \/     \/     \/     \/       
------------  Syn Port Scanner Implementation  ------------"""


def find_lan_ip():
    try:
        getips = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        getips.connect(("1.0.0.1", 53))
        mylanip=getips.getsockname()[0]
        getips.close()
    except:
        mylanip=""
    return mylanip

mylanip = find_lan_ip()
print(banner)
print("[i] My LAN IP is :   ", mylanip)



if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("host", help="Target Host")
    parser.add_argument('-t', '--timeout', type=float, default=1, help="Timeout for socket connection in seconds", required=False)
    args = parser.parse_args()

    try:
        ip_addr = str(IPv4Address(args.host))
    except ValueError:
        ip_addr = socket.gethostbyname(args.host)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.settimeout(1)
    except socket.error as msg:
        print("Socket could not be created. Error code: " + str(msg[0]) + " Message ", msg[1])

    open_ports = []
    for port in tqdm(ports, desc="Scanning Ports"):
        mkpkt = syn.SYNPacket(mylanip, ip_addr, port)
        packet = mkpkt.pack(find_lan_ip(),ip_addr)
        try:
            s.sendto(packet, (ip_addr, 0))
            response = s.recvfrom(1024)
            if response:
                open_ports.append(port)
        except Exception as ex:
            pass
    s.close()
    for port in open_ports:
        print(Style.BRIGHT + Fore.GREEN + f"[{ip_addr}]:{port} -> open" + Fore.RESET)
    
