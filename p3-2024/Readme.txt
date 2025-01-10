P3-Fall2024.py
Input: the name of a .pcap trace file
Output: a set of data relating to the trace file (R1), as well as partial answers to R2.

HOW TO RUN:
python3 P3-FALL2024.py <file name>.pcap

Output (simplified):
=========================================================================================
1	The IP address of the source node (R1)
-----------------------------------------------------------------------------------------
2	The IP address of ultimate destination node (R1)
-----------------------------------------------------------------------------------------
3	The IP addresses of the intermediate destination nodes (R1)
-----------------------------------------------------------------------------------------
4	The correct order of the intermediate destination nodes (R1)
-----------------------------------------------------------------------------------------
5	The values in the protocol field of IP headers (R1)
-----------------------------------------------------------------------------------------
6	The number of fragments created from the orginal datagram (R1)
-----------------------------------------------------------------------------------------
7	The offset of the last fragment (R1)
-----------------------------------------------------------------------------------------
8	The avg RTT to ultimate destination node (R1)
	The avg RTT to intermediate destination nodes
-----------------------------------------------------------------------------------------
9	The std deviation of RTT to ultimate destination node (R1)
	The std deviation of RTT to intermediate destination nodes
-----------------------------------------------------------------------------------------
10	The number of probes per TTL (R2)
	answered separately for both group 1 and group 2
-----------------------------------------------------------------------------------------
11	Right answer to the second question (R2)
	answered separately for both group 1 and group 2
-----------------------------------------------------------------------------------------
12	Right answer to the third/or fourth question (R2)
	answered separately for both group 1 and group 2. For 4, the table will be in P3-Fall2024.pdf
=========================================================================================
