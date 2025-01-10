'''
P3-Fall2024.py
Owen Lutwyche V00977111
The purpose of this program is to identify intermediate routers and RTTs in a wireshark traceroute file.
Given the input %Python3 P3-Fall2024 <filename>.pcap
The program will output the following information:
    1. the IP address of the source node
    2. The IP address of the ultimate destination node
    3. IP addresses of intermediate destination nodes
    4. correct order of the intermediate destination nodes
    5. values in the protocol field of IP headers (only checking pings and responses)
    6. number of fragments created from the original datagram
    7. offset of the last fragment
    8. avg RTT to ultimate destination node, and avg RTT to each intermediate destination node
    9. std deviation of RTT to ultimate destination node, and also of each intermediate node
    10: number of probes per TTL (answered for the two groups of given trace files)
    11: answer to second question from assignment doc (elaborated in P3-Fall2024.pdf
    12: answer to the third and fourth questions from assignment doc (elaborated in P3-Fall2024.pdf)

'''

import struct
import os
import sys
from struct import *
import codecs
import numpy
class Global_header:
    # represents the global header fo the capture file.
    magic_number=None   # 4 bytes
    version_major=None #2bytes
    version_minor=None  # 2 bytes
    thiszone=None   # 4 bytes
    sigfigs=None # 4
    snaplen=None #4
    network=None # 4
    # global header totals 24 bytes.


# this is the IP header struct, from supplemental tutorial code
class IP_Header:
    IHL=0 # THIS IS VERY IMPORTANT! starts at the second byte of the header, andi s 1 byte long!
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    TOS=None
    ID=None
    flags=None
    frag_offset=0
    TTL=0
    protocol=None
    chksum=0
    ICMP_header=None
    UDP_header=None
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def list(self):
        print(("IHL="+str(self.IHL)+"\nTOS="+str(self.TOS)+"\ntotal_len="+str(self.total_len)+"\nID="+str(self.ID)+"\nflags="+str(self.flags)+"\nfrag_offset="+str(self.frag_offset)+"\nTTL="+str(self.TTL)+"\nprotocol="+str(self.protocol)+"\nsrc_ip="+str(self.src_ip)+"\ndst_ip="+str(self.dst_ip)))
        return
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def TOS_set(self,value):
        self.TOS=value
    def ID_set(self,value):
        self.ID=value
    def TTL_set(self,value):
        self.TTL=value
    def protocol_set(self,value):
        self.protocol=value
    def chksum_set(self,value):
        self.chksum=value
    def flags_set(self,value):
        self.flags=value
    def IHL_set(self, value):
        self.IHL=value
    def frag_offset_set(self,value):
        self.frag_offset=value
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)

class TCP_Header:
    # represents the TCP header of a packet

    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    data_size=0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
    
    def list(self):
        print(("src_port="+str(self.src_port)+"\ndst_port="+str(self.dst_port)+"\nseq_num="+str(self.seq_num)+"\nack_num="+str(self.ack_num)+"\ndata_offset="+str(self.data_offset)+"\nflags="+str(self.flags)+"\nwindow_size="+str(self.window_size)+"\nchecksum"+str(self.checksum)+"\nugp="+str(self.ugp)))
        return
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
    
    def data_size_set(self,data_size):
        self.data_size=data_size

    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print("SRC PORT: ", str(self.src_port))
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print("DST PORT: ", str(self.dst_port))
        return None
    
    def get_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        #print("SEQNUM: ", str(seq))
        return None
    
    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    def get_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)
        #print("DATA OFFSET: ", str(self.data_offset))
        return None
    
    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        #print(self.seq_num)
        
    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)
   
class ICMP_Header():
    icmp_type=None
    UDP_header=None
    icmp_code=0
    ID=0
    seq=0
    def set_type(self,value):
        self.icmp_type=value
    def set_UDP_header(self,value):
        self.UDP_header=value
    def code_set(self, THE_NUMBER_THAT_IS_INPUT_TO_THIS_FUNCTION):
        self.icmp_code=THE_NUMBER_THAT_IS_INPUT_TO_THIS_FUNCTION
    def ID_set(self, o):
        self.ID=o
    def seq_set(self,GNRINSAJI):
        self.seq=GNRINSAJI
class Packet():
    # represents a single packet within the capture file

    IP_header = None
    TCP_header = None
    ICMP_header=None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    length=0
    RTT_flag = False
    data_bytes=0
    buffer = None
    response_src=None # THIS IS A VERY IMPORTANT IP ADDRESS!
    response_timestamp=0
    # total 16 bytes
    tpl=tuple()
    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None

    def set_tpl(self):
        tpl=tuple(sorted([self.IP_header.dst_ip, self.IP_header.src_ip]))
        #print(tpl)
        self.tpl=tpl
        return

    def list(self):
        print(("\n\n\ntimestamp="+str(self.timestamp)+"\npacket_No="+str(self.packet_No)+"\nRTT_value="+str(self.RTT_value)+"\nlength="+str(self.length)+"\nRTT_flag="+str(self.RTT_flag)))
        print("\nIP header:")
        self.IP_header.list()
        if(self.TCP_header.src_port!=0):
            print("\nTCP header:")
            self.TCP_header.list()
        
        return
    def timestamp_set(self,buffer1,buffer2,orig_time):
        #seconds = struct.unpack('I',buffer1)[0]
        #microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(buffer1+buffer2*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
    def response_src_set(self, Mikhail_Gorbachev):
        self.response_src=Mikhail_Gorbachev
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)
        self.response_timestamp=p.timestamp
    def get_RTT_value_from_number(self,A_NUMBER_REPRESENTING_TIMESTAMP_OF_ANOTHER_PACKET):
        rtt=A_NUMBER_REPRESENTING_TIMESTAMP_OF_ANOTHER_PACKET-self.timestamp
        self.RTT_value=round(rtt,8)
        self.response_timestamp=A_NUMBER_REPRESENTING_TIMESTAMP_OF_ANOTHER_PACKET
    def set_length(self, l):
        self.length=l
    def data_bytes_set(self, zorgf):
        self.data_bytes=zorgf

class UDP_Header():
    src_port=0
    dst_port=0
    length=0
    def __init__(self):
        return
    def src_port_set(self,value):
        self.src_port=value
        return
    def dst_port_set(self,WHEEEEEEEE):
        self.dst_port=WHEEEEEEEE
        return
class Connection():
    # represents a connection on which one or more packets may be sent between two entities

    ip_1=None # str
    ip_2=None   #str
    port_1=None
    port_2=None


    # SxFy, where x=number of SYN messages and y=number of FIN messages.
    S=0
    F=0
    R=0
    start_time=0 # time of first SYN message between the two IPs
    end_time=0 # time of last FIN message between the two IPs
    duration=0 # time between start and end
    pkts_sent_1=0 # number of packets sent TO ip_1 and FROM ip_2
    pkts_sent_2=0 # number of packets sent TO ip_2 and FROM ip_1
    pkts_sent=0 # =pkts_sent_1+pkts_sent_2

    bytes_sent_1=0 # number of bytes sent TO ip_1 FROM ip_2
    bytes_sent_2=0 # number of bytes sent TO_ip_2 FROM ip_1
    bytes_sent=0 # =bytes_sent_1+bytes_sent_2

    min_RTT=0 # minimum RTT value of all packets sent
    max_RTT=0   # max RTT value of all packets sent
    avg_RTT=0  # average RTT value of all packets sent
    sd_RTT=0 # standard deviation of RTT value of all packets sent
    


    def __init__(self):
        self.ip_1=None
        self.ip_2=None
        self.port_1=None
        self.port_2=None
        self.S=0
        self.F=0
        self.R=0
        self.start_time=0
        self.end_time=0
        self.duration=0
        self.pkts_sent_1=0
        self.pkts_sent_2=0
        self.pkts_sent=0
        self.packets_list=list()


    def list(self):
        # lists the connection in accordance with the assignment's formatting
        R_string=""
        if(self.R>0):
            R_string="/R"

        print(("Source Address: "+str(self.ip_1)+"\nDestination Address: "+str(self.ip_2)+"\nSource Port: "+str(self.port_1)+"\nDestination Port: "+str(self.port_2)+"\nStatus: S"+str(self.S)+"F"+str(self.F)+R_string))
        
        if(self.S>0 and self.F>0):
            print(("Start Time: "+str(self.start_time)+" seconds\nEnd Time: "+str(self.end_time)+" seconds\nDuration: "+str(self.duration)+" seconds\nNumber of packets sent from Source to Destination: "+str(self.pkts_sent_1)+"\nNumber of packets sent from Destination to Source: "+str(self.pkts_sent_2)+"\nTotal number of packets: "+str(self.pkts_sent)+"\nNumber of data bytes sent from Source to Destination: "+str(self.bytes_sent_1)+"\nNumber of data bytes sent from Destination to Source: "+str(self.bytes_sent_2)+"\nTotal number of data bytes: "+str(self.bytes_sent)))
            print("END")
        return
          

    def ip_set(self,ip_1,ip_2):
        self.ip_1=ip_1
        self.ip_2=ip_2
        return
    def port_set(self, port_1, port_2):
        self.port_1=port_1
        self.port_2=port_2
        return

    def SxFy_set(self,S,F):
        self.S=S
        self.F=F
        return
    def start_time_set(self,time):
        self.start_time=float("{0:.6f}".format(time))
    def end_time_set(self,time):
        self.end_time=float("{0:.6f}".format(time))
        self.duration=float("{0:.6f}".format(self.end_time-self.start_time))

    def pkts_sent_1_set(self,pkts):
        self.pkts_sent_1=pkts
    
    def pkts_sent_2_set(self,pkts):
        self.pkts_sent_2=pkts
        self.pkts_sent=(self.pkts_sent_2+self.pkts_sent_1)

    def pkts_sent_set(self, pkts_1, pkts_2):
        self.pkts_sent_1=pkts_1
        self.pkts_sent_2=pkts_2
        self.pkts_sent=pkts_1+pkts_2

    def bytes_sent_set(self, bytes_1, bytes_2):
        self.bytes_sent_1=bytes_1
        self.bytes_sent_2=bytes_2
        self.bytes_sent=bytes_1+bytes_2

    def add_packet(self,packet):
        self.packets_list.append(packet)
        if(len(self.packets_list)==1):
            # first packet, set ip and ports
            self.get_ip()
            self.get_port()
    def list_packets(self):
        for packet in self.packets_list:
            packet.list()
        return

    def count_SxFy(self):
        # count occurrences of each important flag during the connection
        S=0
        F=0
        i=0
        for packet in self.packets_list:
            i+=1
            if(packet.TCP_header.flags["FIN"]==1):
                F+=1
            if(packet.TCP_header.flags["SYN"]==1):
                S+=1
            if(packet.TCP_header.flags["RST"]==1):
                self.R+=1
        self.SxFy_set(S,F)
        #self.list()
        return

    def get_ip(self):
        ip_1=self.packets_list[0].IP_header.src_ip
        ip_2=self.packets_list[0].IP_header.dst_ip
        self.ip_set(ip_1,ip_2)
        return
    
    def get_port(self):
        port_1=self.packets_list[0].TCP_header.src_port
        port_2=self.packets_list[0].TCP_header.dst_port
        self.port_set(port_1,port_2)
        return

    def count_things(self):
        # find the packet in packet list with the earliest timestamp
        first=self.packets_list[0].timestamp
        last=self.packets_list[0].timestamp
        
        valid_RTT_count=0
        pkts_sent_1=0
        pkts_sent_2=0
        RTT_total=0
        avg_RTT=0.0
        sd_RTT=0.0
        bytes_sent_1=0
        bytes_sent_2=0
        last_pkt=None
        #iterate all packets
        print("counthing things for connection "+str(self.ip_1)+", "+str(self.ip_2))
        for packet in self.packets_list:
                
            # update first and last
            if(packet.timestamp<first):
                first=packet.timestamp
            
            # check RTTs
            # we can actually calculate RTTs here since they're already grouped by connection
            this_timestamp=packet.timestamp
            #this_seq=packet.TCP_header.seq_num
            this_no=packet.packet_No
            print("packet "+str(this_no)+" has RTT value "+str(packet.RTT_value))
            if(packet.RTT_value!=0):
                RTT_total+=packet.RTT_value
                valid_RTT_count+=1
        if(valid_RTT_count>0):
            self.avg_RTT=float(RTT_total/valid_RTT_count)
        
        return


'''GLOBAL VARIABLES HERE'''
packet=Packet()
first_timestamp=0
endianness=''

def to_int(bytes_tuple):
    # input: a tuple of bytes read from a file
    # output: an integer value representing the bytes.
    value=0
    if(endianness=='backward'):
    
        for i in reversed(bytes_tuple):
            value <<=8
            value |= i
    else:
        for i in bytes_tuple:
            value<<=8
            value |=i
    return value


def get_bytes(string, length):
    # unpacks the string into a set of bytes of the given length
    #print("unpacking "+str(string)+" for length "+str(length))
    '''
    if(length>1000):
        print("unpacking "+str(length)+" too long lol")
        exit(1)
        '''
    #print("unpacking "+str(string)+" for length "+str(length))
    return struct.unpack(('B'*(length)), string)

def read_global_header(file_file):
    # input: file pointer for the .cap file, pointer located at the beginning
    # output: a global header class instance
    # also changes the global endianness variable.
    # reads the global header of the trace file
    global endianness
    global_header=Global_header()
    length=24
    global_header=file_file.read(length)
    bytes_global_header=get_bytes(global_header,length)
    # first 4 are magic number
    magic_number=bytes_global_header[0:4]
    
    # determine endianness state based on magic number
    if(magic_number[0]>magic_number[3]):
        #print("magic number wrong way round lol")
        endianness='backward'
    else:
        endianness='forward'
    return global_header



def read_packet_header(file_file):
    # input: a file pointer for the .cap file, with the pointer located at the start of a new packet
    # output: a packet instance with some of the fields filled in, specifically the timestamp and length.
    # reads the next 16 bytes of the file to find packet header stuff
    # this WILL CONTAIN PACKET LENGTH!
    global endianness
    global first_timestamp

    endianness='backward'
    packet=Packet()
    #print("reading packet header")
    length=16
    packet_header=file_file.read(length)
    bpkt_hdr=get_bytes(packet_header,length)
    #print(bpkt_hdr)
    time_s=bpkt_hdr[0:4]
    #print("timestamp S ", time_s)
    time_s_int=to_int(time_s)
    #print("timestamp s:", time_s_int)
    time_u=bpkt_hdr[4:8]
    time_u_int=to_int(time_u)
    #print("timestamp u:", time_u_int)  

    time_float_unrounded = float(float(time_s_int)+float(time_u_int*0.000000001))
    time_float = float("{0:.9f}".format(time_float_unrounded))
    #print("timestamp unix: "+str(time_float))

    # WHY IS IT MISREADING THE LENGTH AS LIKE A BILLION???
    #       this was because my trace file was corrupted lol
    # get length of packet
    length=bpkt_hdr[8:12]
    #print(length)
    length_int=to_int(length)
    #print("length of packet: ", length_int)
    
    packet.timestamp=time_float
    if(first_timestamp==0):
        first_timestamp=packet.timestamp
    #print("timestamp "+str(packet.timestamp))

    #print("first timestamp "+str(first_timestamp))
    packet.timestamp=float("{0:.6f}".format(packet.timestamp-first_timestamp))
    #print("adjusted timestamp "+str(packet.timestamp))
    packet.set_length(length_int)
    #print("finished reading packet header")
    #print("timestamp "+str(packet.timestamp))

    return packet

def read_ethernet_header(file_file):
    # input: file pointer for the .cap file, with the pointer located at the start of an ethernet header
    # ethernet header isn't really important, just read it and don't output anything.
    # we could use this later.
    #print("reading ethernet header")
    length=14
    ethernet_header=file_file.read(length)
    bytes_ethernet_header=get_bytes(ethernet_header,length)
    #print(bytes_ethernet_header)
    return

def read_IPv4_header(file_file):
    #input: file pointer for the .cap file, with the pointer located at the start of an IP header
    # output: an IP header class instance
    # reads the IP header and returns an IP_header instance
    global endianness
    endianness='forward'
    ip_header=IP_Header()
    icmp_bits=None
    #print("reading IPv4 header")
    # LENGTH WILL VARY DUE TO OPTIONS AND DATA!
    # 20 bytes at least, but IHL will tell us how much longer 
    # read the first 12 bits
    version_IHL=int_from_file(file_file,1)
    # IHL and version are important
    #print("versiona and IHL:" +str(version_IHL))
    # each is half a byte
    version=version_IHL >> 4
    IHL=version_IHL & 0b1111
    #print("IHL: "+str(IHL))
    #print("version: "+str(version))
    #IHL=int_from_file(file_file,1)
    TOS=int_from_file(file_file,1)
    #print("TOS "+str(TOS))
    total_len=int_from_file(file_file,2)
    #print("total length " +str(total_len))
    ID=int_from_file(file_file,2)
    #print("identification "+str(ID))
    flags_fragment=int_from_file(file_file,2)
    #print("flags and frag offset "+str(flags_fragment))
    #print("flags and frag offset "+f"{flags_fragment:b}")
    flags=flags_fragment >> 3
    flags=flags>>10
    #print("fragmentation flag "+f"{flags:b}")
    #print("flags "+str(flags))
    fragment=flags_fragment & 0b0001111111111111
    #print("fragmentation offset "+f"{fragment:b}")
    #print("as an integer that's "+str(fragment))
    fragment=fragment*8
    #print("total frag offset "+str(fragment))

    TTL=int_from_file(file_file,1)
    protocol=int_from_file(file_file,1)
    chksum=int_from_file(file_file,2)
    
    ip_header.TOS_set(TOS)
    ip_header.ID_set(ID)
    ip_header.TTL_set(TTL)
    ip_header.protocol_set(protocol)
    ip_header.chksum_set(chksum)
    ip_header.IHL_set(IHL)
    ip_header.total_len_set(total_len)
    ip_header.flags_set(flags)
    ip_header.frag_offset_set(fragment)
    # get IP addresses
    src_ip=file_file.read(4)
    dst_ip=file_file.read(4)

    if(ip_header.protocol==1):
       # print("protocol: ICMP")
        #icmp_bits=int_from_file(file_file,8)
        #print("ICMP bits: "+f"{icmp_bits:b}")
        ip_header.ICMP_header=read_ICMP_header(file_file)
    elif(ip_header.protocol==17):
        #print("protocol: UDP")
        ip_header.UDP_header=read_UDP_header(file_file)
    ip_header.get_IP(src_ip, dst_ip)
    #ip_header.list()
    return ip_header

def read_ICMP_header(file_file):
    # input: file pointer to the start of an ICMP header
    # output: ICMP header class insance
    ICMP_header=ICMP_Header()
    nested_UDP=UDP_Header()
    nested_IP=IP_Header()
    icmp_type=0
    icmp_code=0
    seq=0
    chksum=0
    ID=0
    icmp_type=int_from_file(file_file,1)
  #  print("ICMP type "+f"{icmp_type:b}")
    ICMP_header.set_type(icmp_type)
    icmp_code=int_from_file(file_file,1)
    chksum=int_from_file(file_file,2)
    ID=int_from_file(file_file,2)
    seq=int_from_file(file_file,2)
    ICMP_header.code_set(icmp_code)
    ICMP_header.ID_set(ID)
    ICMP_header.seq_set(seq)
 #   print("ICMP sequence "+str(seq))
    if(ICMP_header.icmp_type==11 or ICMP_header.icmp_type==3):
        # this means there's an additional IP and UDP header pointing to the first message
        # case 1: the nested UDP header's source port is the same as that of the original UDP message
   #     print("ICMP error message, reading nested IP header??``")
        nested_IP=read_IPv4_header(file_file)
    #    print("finished reading nested IP header. What did it tell us?")
     #   print("response to IP message from address "+str(nested_IP.src_ip))
      #  print("the ID of this message was "+str(nested_IP.ID))
        if(nested_IP.UDP_header!=None):
       #     print("response to UDP message from source port "+str(nested_IP.UDP_header.src_port))
            ICMP_header.set_UDP_header(nested_IP.UDP_header)
        else:
        #    print("no UDP header, so this message uses sequence numbers to coordinate")
            pass
        if(nested_IP.ICMP_header!=None):
            # OH WHAT THE HELL
            ICMP_header.seq_set(nested_IP.ICMP_header.seq)
    if(ICMP_header.icmp_type==0 or ICMP_header.icmp_type==8):
        # ECHO REPLY OR REQUEST!
        #print("ICMP echo")
        #print("the sequence of this ICMP message is "+str(seq))
        pass
    return ICMP_header

def read_UDP_header(file_file):
    # input: file pointer to the start of a UDP header
    # output: the UDP header as an object
    UDP_header=UDP_Header()
    src_port=int_from_file(file_file,2)
    dst_port=int_from_file(file_file,2)
    #print("soruce port bits" +f"{src_port:b}")
    #print("UDP source port "+str(src_port))
    other_stuff=int_from_file(file_file,2)
    UDP_header.src_port_set(src_port)
    UDP_header.dst_port_set(dst_port)
    #print("other bits "+f"{other_stuff:b}")
    return UDP_header

def int_from_file(file_file, length):
    # input: file pointer and number of bytes to be read
    # output: an integer in a buffer representing the bytes read from the file
    #print("reading file at position "+str(file_file.tell())+" for length "+str(length))
    buffee=file_file.read(length)
    buffee=get_bytes(buffee,length)
    buffee=to_int(buffee)
    #print("value "+str(buffee))
    return buffee

def read_TCP_header(file_file):
    #input: file pointer for the .cap file, with the pointer located at the start of a TCP header
    # output a TCP header class instance
    # reads the TCP header at the current location in the file.
    global endianness
    #global tcp_header
    tcp_header=TCP_Header()
    endianness='forward'
    # try to do this optimally now
    
    # get PORTS!
    buffer1=file_file.read(2)
    buffer1=get_bytes(buffer1,2)
    buffer1=to_int(buffer1)
    tcp_header.src_port_set(buffer1)
    buffer2=file_file.read(2)
    buffer2=get_bytes(buffer2,2)
    buffer2=to_int(buffer2)
    tcp_header.dst_port_set(buffer2)
    
    # get SEQUENCE
    seq_RAW=int_from_file(file_file,4)
    #print("sequence: ",seq_RAW)
    tcp_header.seq_num_set(seq_RAW)
    ack_RAW=int_from_file(file_file,4)
    #print('ack: ', ack_RAW)
    tcp_header.ack_num_set(ack_RAW)
    off=int_from_file(file_file,1)
    # there's 4 reserved bits at the end, but the first 4 bits are the data offset which is needed for getting the length of the header
    # divide by 16 to shift the bits. We can assume the 4 rightmost are 0, so we an remove them by division.
    off=off/16
    #print('offset with the reserved bits removed: ',off)
    tcp_header.data_offset_set(off)

    # data offset represents total header length /4
    # default header length is 20, so default data offset will be 5
    # so length of options is (off*4-20), with trailing 0's to a multiple of 32 bits

    options_length=(off*4)-20
    
    if(options_length==6):
        options_length=8
    elif(options_length==4):
        options_length=6
    

    # what follows is some of the worst code I have ever written
    
    flags=int_from_file(file_file,1)
    flags=list('{0:0b}'.format(flags))
    #print('flags: ',flags)
    # now read from right to left!
    # leftmost = FIN
    # [-1] = SYN
    # [-2] = RST
    # [-3] = PSH
    # [-4] = ACK
    # [-5] = URG
    # [-6] = ECE
    # [-7] = CWR
    flags_array=list()
    flags_index=0
    for flag in reversed(flags):
       # print(flag)
        int_flag=int(flag)
        flags_array.append(int_flag)
    #print(flags_array)
    while(len(flags_array)<8):
        flags_array.append(0)
    flags_array = flags_array[::-1]
    #print(flags_array)
    tcp_header.flags_set(flags_array[-4], flags_array[-3], flags_array[-2], flags_array[-1])

    # worst code completed.


    # WINDOW SIZE!
    window=int_from_file(file_file,2)
    #print('window: ',window)
    tcp_header.win_size_set(window)

    # CHECKSUM!
    chksum=int_from_file(file_file,2)

    # URGENT POINTER!
    urg=int_from_file(file_file,2)
    #print('urgent pointer: ',urg)
    
    # OPTIONS!!!
    #print("reading TCP options")
    for i in range(0,int(options_length)):
        this_option=int_from_file(file_file, 1)
       # print('options: ',this_option)

    return tcp_header

def read_packet_data(file_file, data_length, packet):
    # input: file pointer, length of the current packet, empty packet instance to edit
    # output: the edited  packet instance with its headers filled in
    # also moves the file pointer.
    # this contains Ethernet header, IPv4 header, TCP header, and payload.
    # call the other functions from within here!
    initial_position = file_file.tell()
    read_ethernet_header(file_file)
    packet.IP_header = read_IPv4_header(file_file)
    
    # remaining bytes in this packet constitute data and padding
    #print("data length is "+str(data_length)) 
    #print("finished IP header")
    end_of_header=file_file.tell()
    #print("pointer is at "+str(end_of_header))
    read_bytes=end_of_header-initial_position
    remaining_bytes=data_length-read_bytes
    #print("read bytes: "+str(read_bytes))
    #print("remaining bytes: "+str(remaining_bytes))
    # Sometimes there's IP padding. This can be like 6 bytes right after the TCP URG pointer.  
    # IT's ETHERNET PADDING, 6 bytes added to some packets!
    #print("reading final data bytes")
    last_bytes=int_from_file(file_file, remaining_bytes)
    data_bytes=0
    if(remaining_bytes!=6):
        packet.data_bytes_set(remaining_bytes) 
    # packet 1456 has data in the first three of these bytes!
    elif(remaining_bytes==6):
        if(last_bytes!=0):
            packet.data_bytes_set(3)
    return packet

def list_packets(packets_dict):
    # lists all the packet class instances in a dict of packet class instances.
    # intended for debugging
    for packet in packets_dict:
        packets_dict[packet].list()
    return

class Router():
    # this is one of the routers in the file lol
    ip=None
    packets=[]
    avg_RTT=0
    sd_RTT=0
    def __init__(self):
        return

    def set_ip(self,value):
        self.ip=value
        return
    
    def add_packet(self,packet):
        self.packets.append(packet)
        return

    def get_RTT(self):
        return self.avg_RTT

def read_file(file_name):
    # input: string file name, representing a .cap file
    # output: dict of packet class instances
    # READS THE given .cap file and returns a dict containing all the packets recorded in the file.
    try:
        file_file=open(file_name,'rb')
    except:
        print("invalid file")
        sys.exit(1)
    file_size=os.path.getsize(file_name)
    '''
    GLOBAL HEADER: 24 bytes
    PACKET HEADER: 16 bytes
    PACKET DATA: unknown bytes
    '''
    # get the global header read
    global_header=read_global_header(file_file)   # 24 bytes read!

    # loop, read each packet of the file
    packets_dict=dict()
    i=0
    while True:
        # iterate the file using separate functions, add them to the packets dict!
        #print("\n\n\nbeginning packet number "+str(i+1))
        packet=read_packet_header(file_file)
        packet=read_packet_data(file_file, packet.length, packet)
        packet.packet_No_set(i+1)
        packets_dict[i]=packet
        i+=1
        #print("finished reading packet number "+str(i))
        #packet.list()
        # just go until the pointer leaves the file lol
        if(file_file.tell()>=file_size):
            break
    file_file.close()
    return packets_dict

def tuples_equal(tpl1,tpl2):
    # INPUT: TWO TUPLES, each with only TWO parameters.
    return (sorted(list(tpl1))==sorted(list(tpl2)))

def is_pair_in(tpl, tpl_list):
    # identifies whether a tuple (tpl) is in a list of tuples
    for i in tpl_list:
        if(tuples_equal(tpl,i)):
            return True
    return False

def trace_IP(packets_dict):
    '''
    Input: a dictionary of packets
    Output: the project's final answers
    '''
    # many of these variables aren't going to be used, sorry
    src_ip=None
    dst_ip=None
    dst_rtr=Router()
    intermediate_packets=[]
    intermediate_routers=[]
    protocols_list=[]
    valid_packets=[]
    fragments_count=0
    fragments_dict={}
    last_offset=0
    protocols_dict={1:"ICMP",17:"UDP"}
    protocol_counts={}
    connections_dict={}
    connection_tpl_list=[]
    routers_dict={}
    fragment_ID_list=[]
    last_udp_src=0
    first_udp_src=0
    '''
    requirements:
    IP address of source node
        easy, just pick the first message that mentions 192.168.x.x
    IP address of ultimate destination node
        This isn't just the last message. it could be the final message from a non-local IP?
    IP addresses of intermediate destination nodes
        pick all valid IP addresses that aren't the sender or the final one.
    Values in the protocol field
        need to program a big array for this lol
    fragments and offset of last fragment: 
        iterate the packets, find the packets with MF flag or fragment offset>0. all of these are fragments.
        add all fragments to an array, the last one should have MF==0 and frag offset>0
    average RTTs... reuse logic from the last assignmetn to calculate RTT for a specific router.
    Also add each packet to a table based on router.
    '''
    
    # Iterate the dict of packets to identify router and fragments
    OS="unknown"
    for i in packets_dict:
        packet=packets_dict[i]
        #packet.list()
        protocol=packet.IP_header.protocol

        # make sure the packet is valid
        if(protocol==1 or (protocol==17 and packet.IP_header.UDP_header.dst_port!=53 and packet.IP_header.UDP_header.src_port!=53 and packet.IP_header.UDP_header.src_port!=17500)):
            #if(protocol==17 and packet.IP_header.UDP_header.dst_port!=53 or packet.IP_header.UDP_header.src_port!=53 or packet.IP_header.UDP_header.src_port!=17500)
            #packet.list()
            valid_packets.append(packet)
            this_src=packet.IP_header.src_ip
            this_dst=packet.IP_header.dst_ip
            packet.set_tpl()
            this_tpl=packet.tpl
            this_no=packet.packet_No
            this_MF=packet.IP_header.flags
            this_ID=packet.IP_header.ID
            this_timestamp=packet.timestamp
            this_offset=packet.IP_header.frag_offset
            
            # the external IP address of the packet should be taken as the router

            if(not (this_tpl in connection_tpl_list)):
                connection_tpl_list.append(this_tpl)
                connections_dict[(this_tpl)]=Connection()
            connections_dict[(this_tpl)].add_packet(packet)


            # check source IP
            if(src_ip==None and this_src.startswith("192.168") and protocol==17):
                src_ip=this_src
            if(src_ip==None and this_src.startswith("192.168") and protocol==1):
                if(packet.IP_header.ICMP_header.icmp_type==8):
                    src_ip=this_src
                    dst_ip=this_dst
            # check protocol
            if(protocol in protocol_counts):
                protocol_counts[protocol]+=1
            else:
                protocol_counts[protocol]=1
            
            # check ultimate destination IP? 
            # the last packet to have the destination as the source IP?
            if(dst_ip==None and protocol==17 and this_src==src_ip and packet.IP_header.UDP_header.dst_port!=53):
                dst_ip=this_dst
                #print("destination IP is "+str(dst_ip)+" due to a message with UDP dst port "+str(packet.IP_header.UDP_header.dst_port)) 

            

            # find fragents?
            if(this_MF==1 and not (this_ID in fragment_ID_list)):
                fragment_ID_list.append(this_ID)
                fragments_dict.update({this_ID:[]})
            if(this_ID in fragment_ID_list):
                fragments_dict[(this_ID)].append(packet)
                # this is one of the fragments of some ID in the fragments dict
                if(this_MF==0 and this_offset>0):
                    # last fragment of datagram
                    pass
            # To find the final TTL exceeded message, we need to find something with ICMP that has a nested UDP source port equaling that of the last fragment.
            # on Linux, the RTT requires an ICMP TTL exceeded packet that has a nested UDP header with the same source port as the last fragment.
            # THE UDP SRCPORT IS ACTUALLY STORED IN THE FIRST FRAGMENT!
            # on WINDOWS, the RTT requires an ICMP error message wit the same sequence number as echo message.
            # find RTT for packets. If they're part of a fragment group, calculate RTT for the other fragments as well.
            # LINUX: if this is a UDP packet, find an ICMP TTL exceeded message with anested UDP source address for this packet
            if(protocol==17):
                first_udp_src=packet.IP_header.UDP_header.src_port
                # linux search
                for c in packets_dict:
                    search_pkt=packets_dict[c]
                    if(search_pkt.IP_header.ICMP_header!=None):
                        if(search_pkt.IP_header.ICMP_header.UDP_header!=None):
                            # This is probably a really inefficient way of doing this but I can't just go straight to checking fields of the ICMP_header.UDP_header because they may not exist
                            if(search_pkt.IP_header.ICMP_header.UDP_header.src_port==first_udp_src):
                                # THIS IS THE RESPONSE!
                                #print("match with packet "+str(search_pkt.packet_No))
                                # Calculate RTT
                                packet.get_RTT_value(search_pkt)
                                # now we've found the response message, add packet and all fragments to search_pkt's router
                                packet.response_src_set(search_pkt.IP_header.src_ip)
                                # now that we've found a valid packet following UNIX traceroute protocol, we know this was maed on UNIX os.
                                OS="UNIX"                
           # WINDOWS: if this is an ICMP ping packet, find an ICMP error message with the same sequence
            if(protocol==1):
                # perform a windows search
                if(packet.IP_header.ICMP_header.icmp_type==8):
                    #print("this is a ping, searching for either a reply or error with same sequence number "+str(packet.IP_header.ICMP_header.seq))
                    # search the packets dict, find out if it's an ICMP response, then see if it matches our ping
                    for Y in packets_dict:
                        search_pkt=packets_dict[Y]
                        if(search_pkt.IP_header.ICMP_header!=None):
                            if(search_pkt.IP_header.ICMP_header.seq==packet.IP_header.ICMP_header.seq and search_pkt.packet_No!=packet.packet_No):
                                # match! we foumd the response!
                                packet.get_RTT_value(search_pkt)
                                 # now theoretically we've identified that this is a windows trace file.
                                # that means we can ignore ALL UDP packets! set OS to BINDOES so we know to ignore them for quedstion 5 or whatever
                                packet.response_src_set(search_pkt.IP_header.src_ip)
                                OS='BINDOES'
                                 # check all fragmented messages for ones that don't have an RTT and calculate it based on the RTT of the first message!
    for t in fragments_dict:
        for w in fragments_dict[(t)]:
            if(w.RTT_value==0):
                # good thing we saved the timestamp of the response to the first fragment!
                if(fragments_dict[(t)][0].response_timestamp!=0):                
                    w.get_RTT_value_from_number(fragments_dict[(t)][0].response_timestamp)
                    w.response_src_set(fragments_dict[(t)][0].response_src)
    # create a list of intermediate routers!
    intermediate_ips=[]
    for tpl in connections_dict.keys():
        this_connection=connections_dict[(tpl)]
        if(this_connection.ip_1!= dst_ip and this_connection.ip_1!=src_ip and not this_connection in intermediate_routers):
            intermediate_routers.append(this_connection)
            intermediate_ips.append(this_connection.ip_1)

# group packets based on router    
    routers_RTT_dict={}
    #print("grouping packets based on router, finallY!")
    valid_rsp_count=0
    for w in packets_dict:
        packet=packets_dict[w]
        # find a response to the packet, link them together
        if(packet.response_src!=None):
            valid_rsp_count+=1
            this_rsp=packet.response_src
            if not (this_rsp in routers_dict.keys()):
                # create entry in dicts if we don't already have one
                routers_dict[(this_rsp)]=[]
                routers_RTT_dict[(this_rsp)]=[0,0]
            routers_dict[(this_rsp)].append(packet) 
    # R2 requires checking average RTT per TTL (hop distance)
    RTT_TTL_dict={}

    # GET AVERAGE RTTS
    for r in routers_dict:
        router=routers_dict[(r)]
        total_RTT=0.0
        avg_RTT=0.0
        sd_RTT=0.0
        RTT_array=[]
        for paccett in router:
            # get totals
            if(paccett.RTT_value!=0):
                total_RTT+=paccett.RTT_value
                RTT_array.append(paccett.RTT_value)
                if(not paccett.IP_header.TTL in RTT_TTL_dict.keys()):
                    RTT_TTL_dict[(paccett.IP_header.TTL)]=[]
                RTT_TTL_dict[(paccett.IP_header.TTL)].append(paccett.RTT_value)

        # floating point calculations
        avg_RTT=float(total_RTT/len(router))
        sd_RTT=numpy.std(RTT_array)
        # convert to MS
        avg_RTT=avg_RTT*1000
        sd_RTT=sd_RTT*1000
        
        # put it in a 2-entry array!
        routers_RTT_dict[r][0]=round(avg_RTT,6)
        routers_RTT_dict[r][1]=round(sd_RTT,6)
    
    # solve R2 q4, output average RTT for each TTL value
    # this was just for debugging
    for T in RTT_TTL_dict:
        avg_RTT=round((numpy.mean(RTT_TTL_dict[T])*1000),6)
        #print("TTL="+str(T)+" avg RTT is "+str(avg_RTT))
    

        # ANSWERS !!!
    
    print(f"{'Row':<5}{'Components':<60}{'Details'}")
    print("="*90)
    print(f"{'1':<5}{'The IP address of the source node (R1)':<60}{src_ip}")
    
    print("-"*90)
    print(f"{'2':<5}{'The IP address of the ultimate destination node (R1)':<60}{dst_ip}")

    
    print("-"*90)
    
    print(f"{'3':<5}{'The IP addresses of the intermediate destination nodes (R1)':<60}{', '.join(intermediate_ips)}")
    print("-"*90)
    print(f"{'4':<5}{'The correct order of the intermediate destination nodes (R1)':<60}{', '.join(intermediate_ips)}")
    print("-"*90)
    
    #remove UDP representing DNS packets on windows trace files 
    if(OS=="BINDOES" and 17 in protocol_counts.keys()):
        del protocol_counts[17]
    protocol_details=",".join(f"{p}:{'ICMP' if p == 1 else 'UDP' if p == 17 else 'Unknown'}" for p in protocol_counts.keys())
    print(f"{'5':<5}{'The values in the protocol field of IP headers (R1)':<60}{protocol_details}")
    
    print("-"*90)
   
    first_loop=1
    for ID in fragments_dict:
        count=len(fragments_dict[ID])
        print(f"{'6':<5}{'The number of fragments created from the original datagram (R1) ':<60}{str(count)}")
        
        # find the offset of the last datagram
        for packet in fragments_dict[ID]:
            if(last_offset<packet.IP_header.frag_offset):
                last_offset=packet.IP_header.frag_offset
        print(f"{'7':<5}{'The offset of the last fragment (R1)':<60}{last_offset}")
        break # it turns out we're only supposed to print this once.

    # if unfragmented, print 0s
    if(len(fragments_dict)==0):
        print(f"{'6':<5}{'The number of fragments created from the original datagram (R1)':<60}{'0'}")
        print(f"{'7':<5}{'The offset of the last fragment (R1)':<60}{'0'}")
 
    ult_dst_avg_RTT=routers_RTT_dict[dst_ip][0]
    ult_dst_sd_RTT=routers_RTT_dict[dst_ip][1]
    print("-"*90)
    print(f"{'8':<5}{'The avg RTT to ultimate destination node (R1)':<60}{ult_dst_avg_RTT} ms")

    for r in reversed(routers_RTT_dict):
        if(r!=dst_ip):
            print("\tThe avg RTT between "+str(src_ip)+" and "+str(r)+" is: "+str(routers_RTT_dict[r][0])+" ms")
        
    print("-"*90) 
    print(f"{'9':<5}{'The std deviation of RTT to ultimate destination node (R1)':<60}{ult_dst_sd_RTT} ms")
    for r in reversed(routers_RTT_dict):
        if(r!=dst_ip):
            print("\tThe std deviation of RTT between "+str(src_ip)+" and "+str(r)+" is: "+str(routers_RTT_dict[r][1])+" ms")
    
    print("-"*90)
    probes_per_ttl_1={1:3,2:3,3:3,4:3,5:3,6:3,7:3,8:3,9:3,10:3,11:3,12:3,13:3,14:3,15:3,16:3,17:3}
    probes_per_ttl_2={1:3,2:3,3:3,4:3,5:3,6:3,7:3,8:3,9:3}
   

    print(f"{'10':<5}{'The number of probes per TTL for group 1 (R2)':<60}{', '.join(f'TTL {ttl}: {probes}' for ttl, probes in probes_per_ttl_1.items())}")
    print(f"{'':<5}{'The number of probes per TTL for group 2 (R2)':<60}{', '.join(f'TTL {ttl}: {probes}' for ttl, probes in probes_per_ttl_2.items())}")

    print("-"*90) 
    answer_second_question_1="no"
    answer_second_question_2="yes"
    answer_third_question_1="The sequence is different. Many of the routers appear in a different order depending on trace file. Most importantly, the router 74.125.37.91 is absent from trace5."
    answer_third_question_2="The sequence is the same. Table is located in the PDF. TTL 8 has the highest mean of average RTT, so it is likely that hop #8 will incur the maximum delay."
    print(f"{'11':<5}{'Right answer to the second question for group 1 (R2)':<60}{answer_second_question_1}")
    print(f"{'':<5}{'Right answer to the second question for group 2 (R2)':<60}{answer_second_question_2}")
    print("-"*90)
    print(f"{'12':<5}{'Right answer to the third/or fourth question for group 1 (R2)':<60}{answer_third_question_1}")
    print(f"{'':<5}{'Right answer to the third/or fourth question for group 2 (R2)':<60}{answer_third_question_2}")
    print("="*90)
    return


def main():
    # get the filename which was passed as the program's argument.
    try:
        
        file_name=sys.argv[1]
    except:
        print("please enter a valid file name")
        sys.exit(1)
    # read the file to get a dict of packets
    packets_dict=read_file(file_name)
    # examine the dict of packets to identify connections and print them.
    #find_connections(packets_dict)
    trace_IP(packets_dict)
    return


if __name__=='__main__':
    main()

