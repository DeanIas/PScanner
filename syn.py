import socket,struct

class SYNPacket:
    def __init__(self, source_ip, dest_ip,dest_port):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        
        
        # ip header fields
        self.ihl = 5
        self.version = 4
        self.tos = 0
        self.tot_len = 20 + 20
        self.id = 54321 
        self.frag_off = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.check = 10 # filled by kernel 
        self.s_addr = socket.inet_aton( self.source_ip ) 
        self.d_addr = socket.inet_aton( self.dest_ip )
        self.ihl_version = (self.version << 4) + self.ihl

        self.ip_header = struct.pack("!BBHHHBBH4s4s", self.ihl_version, self.tos, self.tot_len, self.id ,self.frag_off, self.ttl, self.protocol, self.check, self.s_addr, self.d_addr)

        # tcp header fields
        self.source = 1234   # source port
        self.dest = dest_port   # destination port
        self.seq = 0
        self.ack_seq = 0
        self.doff = 5    #5 * 4 = 20 bytes
        #tcp flags
        self.fin = 0
        self.syn = 1
        self.rst = 0
        self.psh = 0
        self.ack = 0
        self.urg = 0
        self.window = socket.htons(5840)
        self.check = 0
        self.urg_ptr = 0

    def pack(self, source, destination):
        offset_res = (self.doff << 4) + 0
        tcp_flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
        tcp_header = struct.pack("!HHLLBBHHH",
                                 self.source,
                                 self.dest,
                                 self.seq,
                                 self.ack_seq,
                                 offset_res,
                                 tcp_flags,
                                 self.window,
                                 self.check,
                                 self.urg_ptr)
        # pseudo header fields
        source_address = socket.inet_aton( source )
        dest_address = socket.inet_aton(destination)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        # Pseudo Header
        psh = struct.pack("!4s4sBBH", 
                          source_address,
                          dest_address,
                          placeholder,
                          protocol,
                          tcp_length)
        psh = psh + tcp_header
        tcp_checksum = checksum(psh)
        tcp_header = struct.pack('!HHLLBBHHH' , 
                                      self.source, 
                                      self.dest, 
                                      self.seq, 
                                      self.ack_seq, 
                                      offset_res, 
                                      tcp_flags,  
                                      self.window,
                                      tcp_checksum , 
                                      self.urg_ptr
                                      )
        packet = self.ip_header + tcp_header
        return packet


def checksum(msg):
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
