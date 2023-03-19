import socket,struct

class SYNPacket:
    def __init__(self, source_ip, dest_ip,dest_port):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        
        self.packet = ''
        
        # ip header fields
        self.ihl = 5
        self.version = 4
        self.tos = 0
        self.tot_len = 20 + 20 # python seems to fill the total length
        self.id = 54321 # import random
        self.frag_off = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.check = 10 # filled by kernel 
        self.s_addr = socket.inet_aton( self.source_ip ) # spoof it
        self.d_addr = socket.inet_aton( self.dest_ip )
        self.ihl_version = (self.version << 4) + self.ihl

        self.ip_header = struct.pack("!BBHHHBBH4s4s", self.ihl_version, self.tos, self.tot_len, self.id ,self.frag_off, self.ttl, self.protocol, self.check, self.s_addr, self.d_addr)

        # tcp header fields
        self.source = 1234   # source port
        self.dest = dest_port   # destination port
        self.seq = 0
        self.ack_seq = 0
        self.doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        self.fin = 0
        self.syn = 1
        self.rst = 0
        self.psh = 0
        self.ack = 0
        self.urg = 0
        self.window = socket.htons(5840)    #   maximum allowed window size
        self.check = 0
        self.urg_ptr = 0

        self.offset_res = (self.doff << 4) + 0
        self.tcp_flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh <<3) + (self.ack << 4) + (self.urg << 5)
        self.tcp_header = struct.pack("!HHLLBBHHH",
                                 self.source,
                                 self.dest,
                                 self.seq,
                                 self.ack_seq,
                                 self.offset_res,
                                 self.tcp_flags,
                                 self.window,
                                 self.check,
                                 self.urg_ptr)
        # Pseudo Header
        self.source_address = socket.inet_aton( self.source_ip )
        self.dest_address = socket.inet_aton(self.dest_ip)
        self.placeholder = 0
        self.protocol = socket.IPPROTO_TCP
        self.tcp_length = len(self.tcp_header)
        self.psh = struct.pack("!4s4sBBH", 
                          self.source_address,
                          self.dest_address,
                          self.placeholder,
                          self.protocol,
                          self.tcp_length
                          )
        self.psh = self.psh + self.tcp_header
        self.tcp_checksum = self.checksum(self.psh)
        self.tcp_header = struct.pack('!HHLLBBHHH' , 
                                      self.source, 
                                      self.dest, 
                                      self.seq, 
                                      self.ack_seq, 
                                      self.offset_res, 
                                      self.tcp_flags,  
                                      self.window,
                                      self.tcp_checksum , 
                                      self.urg_ptr
                                      )
        self.packet = self.ip_header + self.tcp_header

    def checksum(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ((msg[i]) << 8) + ((msg[i+1]) )
            s = s + w

        s = (s>>16) + (s & 0xffff)
        #s = s + (s >> 16);
        #complement and mask to 4 byte short
        s = ~s & 0xffff

        return s
    
    def socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.settimeout(1) # for slow hosts
        except socket.error as msg:
            print("Socket could not be created. Error code: " + str(msg[0]) + " Message ", msg[1])
        return s
    def connect(self, sd):
        try:
            sd.sendto(self.packet, (self.dest_ip , 0 ))
            #print("[+] Packet Sent") # debug
            response = sd.recvfrom(1024)
            sd.close()
            if response:
                print("\n\r[+] Reiceved: ", response[0])
                return True
        except Exception as ex:
            #print("Exception Occured: " , ex)
            sd.close()

def find_lan_ip():
    try:
        getips = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        getips.connect(("1.0.0.1", 53))
        mylanip=getips.getsockname()[0]
        getips.close()
    except:
        mylanip=""
    return mylanip