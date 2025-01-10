P2-2024
Owen Lutwyche V00977111

This program takes the name of a .cap trace file and outputs information on TCP connections
that it detects within the file.
works by reading the headers of each packet in the file, then iterates through the packets to identify which ones were sent along the same connection.
NOTE: it is very important that the program is run using "python". that is the command that was used to test in on linux.csc.uvic.ca.

HOW TO RUN:
%python TCPTracer.py <filename>.cap

OUTPUT:
A) Total number of connections
______________________________________________

B) Connections's details:

Connection 1:
Source Address
Destination Address
Source Port
Destination Port
Status: SxFy /R 
IF COMPLETED: output the below information
Start time
End Time
Duration
Number of packets sent from source to destination
Number of packets sent from destination to source
Total number of packets
Number of data bytes sent from source to desitnation
Number of data bytes sent from destination to source
total number of data bytes
END
++++++++++++++++++++++++++++++++++++++
...
++++++++++++++++++++++++++++++++++++++
...
repeat until connection N
___________________________________________

C) General

Total number of complete TCP connections
Number of reset TCP connections
Number of TCP connections that were still open when the trace capture ended
______________________________________________

D) Complete TCP connections

Min time duration
Mean time duration
Max time duration

Min RTT
Mean RTT
Max RTT

Min number of packets including both send/received
Mean number of packets including both send/received
Max number of packets including both send/received

Min receive window size including both send/received
Mean receive window size including both send/received
Max receive window size including both send/received
