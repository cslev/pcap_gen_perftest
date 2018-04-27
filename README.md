# pcap_gen_perftest
This python script can be used to demonstrate the performance of PCAP file generation from python, i.e., to measure how much time does it take to generate IP packets with SCAPY (python-scapy) or by low level tools handcrafting the pcap files manually by writing HEX numbers to a file.

usage: python pcap_gen_perftest.py -b <backend> -o <OUTPUT> [-n <#flows>  -s <PACKETSIZE>]

Usage of PCAP generator performance tester
```
optional arguments:
  - -h, --help            show this help message and exit
  
  - -b BACKEND, --backend BACKEND
    Specify the backend.
 
    SCAPY will use scapy library to craft the packets and write out the pcap file
 
    HEX will create the pcaps by writing HEX strings/numbers into the file directly
  
  - -o OUTPUT, --output OUTPUT
  
    Specify the output PCAP file's basename! Output will be [output].[PACKETSIZE]bytes.pcap extension is not needed!
  
  - -s PACKETSIZES, --packetsizes PACKETSIZES
     
    Specify here the required packetsize! In case of more than one, just create a comma separated list such as 64,112,42. Default: 64
    
  - -n NUM, --num NUM     Specify the number of flows to create - Default: 100
```

A good example to test the performance is to generate ca. 100.000 flows and use Linux's built-in *time* script for printing out the elapsed time.

So, first let's generate 10.000 random 64-byte sized IP packets with SCAPY using the following command:
```
$ time python pcap_gen_perftest.py -b SCAPY -o gen_by_scapy -n 10000 -s 64
```
This will produce a *gen_by_scapy.64bytes.pcap* file, and the output of *time* prints out (on my laptop) the following:
```
real	0m14.057s
user	0m14.008s
sys	0m0.044s
```
As one can observe, using the high level python-scapy library for generating 10.000 packets would require ca. 15 sec.

Let's examine, how the performance changes when we directly write out the HEX numbers into a PCAP file by using low-level tools.
```
$ time python pcap_gen_perftest.py -b HEX -o gen_by_scapy -n 10000 -s 64
```
This will produce a *gen_by_hex.64bytes.pcap* file, and the output of *time* prints out (on my laptop) the following:
```
real	0m1.066s
user	0m0.880s
sys	0m0.060s
```
One can observe that it is at least one order of magnitude faster.

Try this on your own machine with much more packets per pcap file and you will realize that python-scapy could take approximately an hour for generating 1.000.000 packets compared to a couple of minutes provided by the low-level tools.

On my laptop, I have measured the following (results are in seconds):


| Method/#packets |  1000  | 10.000 | 100.000 | 1.000.000 |
| --------------- |:-----:| :----: | :------: | :-------: |
| HEX             | 0.354 | 0.354  | 8.174    |  77.735   |
| SCAPY           | 1.604 | 13.573 | 195.227  | 2375.173  | 


One can not just observe the performance advantage of the HEX backend, but the performance is a linear function of the required number of packets, which does not apply for the SCAPY backend.
