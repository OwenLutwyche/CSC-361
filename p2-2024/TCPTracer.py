'''
The purpose of this program is to identify connections within a wireshark capture file.
Given the input %Python TCPTracer.py <filename>.cap
The program will output the following information:
    A) total number of connections detected
    B) a list of the connections, their state, timeframe, and tuples.
    C) general information on the number of complete connections and number of reset connections
    D) statistics on the complete TCP connections, namely, the min, mean, and max of:
        time duration
        RTT value
        number of packets including both send/received
        received window size including both send/received

'''

import struct
import os
import sys
from struct import *
import codecs

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
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def list(self):
        print("IHL="+str(self.IHL)+"\nsrc_ip="+str(self.src_ip)+"\ndst_ip="+str(self.dst_ip)+"\nip_header_len="+str(self.ip_header_len)+"\ntotal_len="+str(self.total_len))
        return
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def IHL_set(self, value):
        self.IHL=value

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
        print("src_port="+str(self.src_port)+"\ndst_port="+str(self.dst_port)+"\nseq_num="+str(self.seq_num)+"\nack_num="+str(self.ack_num)+"\ndata_offset="+str(self.data_offset)+"\nflags="+str(self.flags)+"\nwindow_size="+str(self.window_size)+"\nchecksum"+str(self.checksum)+"\nugp="+str(self.ugp))
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
   

class Packet():
    # represents a single packet within the capture file

    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    length=0
    RTT_flag = False
    data_bytes=0
    buffer = None
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
        tpl=tuple(sorted([self.IP_header.dst_ip, self.IP_header.src_ip, self.TCP_header.dst_port, self.TCP_header.src_port]))
        #print(tpl)
        self.tpl=tpl
        return

    def list(self):
        print("\n\n\ntimestamp="+str(self.timestamp)+"\npacket_No="+str(self.packet_No)+"\nRTT_value="+str(self.RTT_value)+"\nlength="+str(self.length)+"\nRTT_flag="+str(self.RTT_flag))
        print("\nIP header:")
        self.IP_header.list()
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
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)
    def set_length(self, l):
        self.length=l
    def data_bytes_set(self, zorgf):
        self.data_bytes=zorgf


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
    mean_RTT=0  # average RTT value of all packets sent

    


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

        print("Source Address: "+str(self.ip_1)+"\nDestination Address: "+str(self.ip_2)+"\nSource Port: "+str(self.port_1)+"\nDestination Port: "+str(self.port_2)+"\nStatus: S"+str(self.S)+"F"+str(self.F)+R_string)
        
        if(self.S>0 and self.F>0):
            print("Start Time: "+str(self.start_time)+" seconds\nEnd Time: "+str(self.end_time)+" seconds\nDuration: "+str(self.duration)+" seconds\nNumber of packets sent from Source to Destination: "+str(self.pkts_sent_1)+"\nNumber of packets sent from Destination to Source: "+str(self.pkts_sent_2)+"\nTotal number of packets: "+str(self.pkts_sent)+"\nNumber of data bytes sent from Source to Destination: "+str(self.bytes_sent_1)+"\nNumber of data bytes sent from Destination to Source: "+str(self.bytes_sent_2)+"\nTotal number of data bytes: "+str(self.bytes_sent))
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
        
        
        pkts_sent_1=0
        pkts_sent_2=0
        RTT_total=0
        bytes_sent_1=0
        bytes_sent_2=0
        
        #iterate all packets
        for packet in self.packets_list:
                
            # update first and last
            if(packet.timestamp<first):
                first=packet.timestamp
            
            # the last packet has to be a FIN message!
            if(packet.timestamp>last and packet.TCP_header.flags["FIN"]==1):
                last=packet.timestamp
            # check IP address to see where the packet went
            if(packet.IP_header.src_ip==self.ip_1):
                pkts_sent_1+=1
                bytes_sent_1+=packet.data_bytes
            elif(packet.IP_header.src_ip==self.ip_2):
                pkts_sent_2+=1
                bytes_sent_2+=packet.data_bytes
            else:
                packet.list()
                sys.exit(1)
        
            
            # check RTTs
            # we can actually calculate RTTs here since they're already grouped by connection
            this_timestamp=packet.timestamp
            this_seq=packet.TCP_header.seq_num
            this_no=packet.packet_No
            this_bytes=packet.data_bytes

            # need to find a message acknowledging this message's seq+len
            if(this_bytes>0):
                target_ack=this_seq+this_bytes
                this_flags=packet.TCP_header.flags
                
                # NOW, find a packet with ack = this_seq+this_bytes
                # AND packet_No>this_no
                for pkt in self.packets_list:
                    
                    other_no=pkt.packet_No
                    other_ack=pkt.TCP_header.ack_num
                    #determine whether this is the correct response
                    if(other_ack==target_ack and other_no>this_no):
                        response=pkt
                        packet.get_RTT_value(response)
                        break
        
        # apply everything
        self.start_time_set(first)
        self.end_time_set(last)
        self.pkts_sent_set(pkts_sent_1, pkts_sent_2)
        self.bytes_sent_set(bytes_sent_1, bytes_sent_2)
        
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
    
    
    # get length of packet
    length=bpkt_hdr[8:12]
    length_int=to_int(length)
    #print("length of packet: ", length_int)
    packet.timestamp_set(time_s_int, time_u_int, 0.0)
    if(first_timestamp==0):
        first_timestamp=packet.timestamp
    
    packet.timestamp=packet.timestamp-first_timestamp
    packet.set_length(length_int)
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
    ip_header=IP_Header()
    # LENGTH WILL VARY DUE TO OPTIONS AND DATA!
    # 20 bytes at least, but IHL will tell us how much longer 
    
    # start by finding IHL in the first 12 bytes
    length=12
    ip_header_str=file_file.read(length)
    bytes_ip_header=get_bytes(ip_header_str,length)
    #print(bytes_ip_header)
    # get the second byte for IHL
    IHL_byte=bytes_ip_header[1]
    IHL = (IHL_byte)
    ip_header.IHL_set(IHL)
    
    # get IP addresses
    src_ip=file_file.read(4)
    dst_ip=file_file.read(4)
    ip_header.get_IP(src_ip, dst_ip)
    if(IHL>0):
        options=file_file.read(IHL)
    return ip_header

def int_from_file(file_file, length):
    # input: file pointer and number of bytes to be read
    # output: an integer in a buffer representing the bytes read from the file
    buffee=file_file.read(length)
    buffee=get_bytes(buffee,length)
    buffee=to_int(buffee)
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
    for i in range(0,options_length):
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
    #print('current position in file '+str(initial_position))


    read_ethernet_header(file_file)
    
    packet.IP_header = read_IPv4_header(file_file)
    packet.TCP_header = read_TCP_header(file_file)
    packet.set_tpl()
    #packet.list()

    # remaining bytes in this packet constitute data and padding
    end_of_header=file_file.tell()
    read_bytes=end_of_header-initial_position
    remaining_bytes=data_length-read_bytes
    # Sometimes there's IP padding. This can be like 6 bytes right after the TCP URG pointer.  
    # IT's ETHERNET PADDING, 6 bytes added to some packets!
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
        packet=read_packet_header(file_file)
        packet=read_packet_data(file_file, packet.length, packet)
        packet.packet_No_set(i+1)
        packets_dict[i]=packet
        i+=1

        # just go until the pointer leaves the file lol
        if(file_file.tell()>=file_size):
            break
    file_file.close()
    return packets_dict

def tuples_equal(tpl1,tpl2):
    return (sorted(list(tpl1))==sorted(list(tpl2)))

def is_pair_in(tpl, tpl_list):
    for i in tpl_list:
        if(tuples_equal(tpl,i)):
            return True
    return False

def find_connections(packets_dict):
    # search the dict of packets and identify which ones share the same tuples.
    # then calculate the assignment's final answers and print them.
    connections_dict=dict()
    ip_pairings_list=list()
    port_pairings_list=list()
    complete_connection_packets=list()
    connection_tpl_list=list()
    index=0
    for packet in packets_dict:
        this_pkt=packets_dict[packet]
        # go until we find a new connection tuple. When we've found all tuples, go to another function that iterates the dict and analyzes all packets associated with that tuple
        this_pkt_tpl=tuple(sorted([this_pkt.IP_header.src_ip, this_pkt.TCP_header.src_port, this_pkt.IP_header.dst_ip, this_pkt.TCP_header.dst_port]))

       # it's ok if we sort the ips and ports for the purposes of recording connections, as the packet themselves will remain unchanged and are added so we can still count number of packets in each direction 

        if(this_pkt_tpl in connection_tpl_list):
            #the tpl list already has this tuple in it, we don't need to make a new entry
            pass 
        else:
            # create a new entry in the tpl list for this newly-discovere tuple
            # first occurrence of this tpl has been found
            connection_tpl_list.append(this_pkt_tpl)
            connections_dict[(this_pkt_tpl)]=Connection()

        # add the message to the list of packets with matching tuple.
        connections_dict[(this_pkt_tpl)].add_packet(this_pkt)
       
    #we now have a big dict grouping messages by connection tuples
    # find which packet groups form a complete connection
    
    completed_connections=list()
    i=0
    completed_count=0
    packet_count=0
    reset_count=0

    # iterate the list of connections, count number of complete connections
    for tpl in connections_dict.keys():
        this_connection=connections_dict[(tpl)]
        
        this_connection.count_SxFy()
        
    
        if(this_connection.R>0):
            reset_count+=1
        if(this_connection.S>0 and this_connection.F>0):
            completed_connections.append(this_connection)
            for packet in this_connection.packets_list:
                complete_connection_packets.append(packet)

        # get other information that needs to be printed as part of the complete connection output
                this_connection.count_things()
            completed_count+=1

# print the part A output
        i+=1 
    print("A) Total number of connections: "+str(len(connections_dict))+"\n________________________________________________\n\nB) Connection's details\n")

    # PART B: list all connections

    i=1
    connections_list=list()
    for key in sorted(connections_dict, key=lambda name: connections_dict[name].port_1):
        print("Connection: "+str(i)+":")
        #print(key)
        i+=1
        connections_dict[(key)].list()
        
        #print("END")
        
        if(i<len(connections_dict)+1):
            print("++++++++++++++++++++++++++++++++")

    # PART C
    # get counts of complete, reset, still open, and previously established TCP connections
    # since we're gonna be iterating the dict might as well handle part D's counting too

    total_open=0
    total_prev_est=0
    # count the number of open/previously established connections
    for tpl in connections_dict.keys():
        this_connection=connections_dict[(tpl)]

        this_S=this_connection.S
        this_F=this_connection.F
        if(this_S==0 and this_F>0):
            total_prev_est+=1
        elif(this_S>0 and this_F==0):
            total_open+=1

    # print the part C output
    print("________________________________________________\n\nC) General\n\nThe total number of complete TCP connections: "+str(completed_count))
    if(reset_count>0):
        print("The number of reset TCP connections: "+str(reset_count))
    if(total_open>0):
        print("The number of TCP connections that were still open when the trace capture ended: "+str(total_open))
    if(total_prev_est>0):
        print("The number of TCP connections established before the capture started: "+str(total_prev_est))

    # PART D
    # get data on complete TCP connections
    min_RTT=complete_connection_packets[0].RTT_value
    mean_RTT=0
    total_RTT=0
    max_RTT=complete_connection_packets[0].RTT_value
    min_win=complete_connection_packets[0].TCP_header.window_size
    mean_win=0
    total_win=0
    max_win=complete_connection_packets[0].TCP_header.window_size
    

    min_duration=completed_connections[0].duration
    max_duration=min_duration
    total_duration=0
    min_pkts=completed_connections[0].pkts_sent
    max_pkts=min_pkts
    total_pkts=0

 
    # identify min/mean/max RTT values
    for packet in complete_connection_packets:
        
        if(packet.RTT_value<min_RTT and packet.RTT_value>0.0):
            min_RTT=packet.RTT_value
        if(packet.RTT_value>max_RTT):
            max_RTT=packet.RTT_value
        total_RTT+=packet.RTT_value
        
        if(packet.TCP_header.window_size<min_win):
            min_win=packet.TCP_header.window_size
        if(packet.TCP_header.window_size>max_win):
            max_win=packet.TCP_header.window_size
        total_win+=packet.TCP_header.window_size
    
# format the floats
    mean_RTT=total_RTT/len(complete_connection_packets)
    mean_win=float(float(total_win)/float(len(complete_connection_packets)))
    mean_RTT=float("{0:.6f}".format(mean_RTT))
    mean_win=float("{0:.6f}".format(mean_win))
    min_RTT=float("{0:.6f}".format(min_RTT))
    max_RTT=float("{0:.6f}".format(max_RTT))

 # identify min/mean/max durations and packets sent
    for connection in completed_connections:
        
        this_duration=connection.duration
        if(this_duration<min_duration):
            min_duration=this_duration
        elif(this_duration>max_duration):
            max_duration=this_duration
        total_duration+=this_duration

    
        this_pkts=connection.pkts_sent
        if(this_pkts<min_pkts):
            min_pkts=this_pkts
        elif(this_pkts>max_pkts):
            max_pkts=this_pkts
        total_pkts+=this_pkts

# format the floats
    mean_duration=total_duration/len(completed_connections)
    mean_pkts=float(float(total_pkts)/float(len(completed_connections)))
    mean_duration=float("{0:.6f}".format(mean_duration))
    mean_pkts=float("{0:.6f}".format(mean_pkts))
    min_duration=float("{0:.6f}".format(min_duration))
    max_duration=float("{0:.6f}".format(max_duration))

# print the part D output
    print("________________________________________________\n\nD) Complete TCP connections\n\nMinimum time duration: "+str(min_duration)+" seconds")
    print("Mean time duration: "+str(mean_duration)+" seconds")
    print("Maximum time duration: "+str(max_duration)+" seconds")

    print("\n\nMinimum RTT value: "+str(min_RTT)+"\nMean RTT value: "+str(mean_RTT)+"\nMaximum RTT value: "+str(max_RTT))
    print("\n\nMinimum number of packets including both send/received: "+str(min_pkts)+"\nMean number of packets including both send/received: "+str(mean_pkts)+"\nMaximum number of packets including both send/received: "+str(max_pkts))
     
    print("\n\nMinimum receive window size including both send/received: "+str(min_win)+" bytes\nMean receive window size including both send/received: "+str(mean_win)+" bytes\nMaximum receive window size including both send/received: "+str(max_win)+" bytes\n________________________________________________")

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
    find_connections(packets_dict)
    return


if __name__=='__main__':
    main()
