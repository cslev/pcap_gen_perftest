# pcap_gen_perftest
This python script can be used to demonstrate the performance of PCAP file generation from python, i.e., to measure how much time does it take to generate IP packets with SCAPY (python-scapy) or by low level tools handcrafting the pcap files manually by writing HEX numbers to a file.

usage: python pcap_gen_perftest.py -b <backend> -o <OUTPUT> [-n <#flows>  -s <PACKETSIZE>]

Usage of PCAP generator performance tester

optional arguments:
  - -h, --help            show this help message and exit
  
  - -b BACKEND, --backend BACKEND
    - Specify the backend.
 
                        SCAPY will use scapy library to craft the packets and write out the pcap file

                        HEX will create the pcaps by writing HEX strings/numbers into the file directly
  -o OUTPUT, --output OUTPUT
                        Specify the output PCAP file's basename! Output will be [output].[PACKETSIZE]bytes.pcap extension is not needed!
  -s PACKETSIZES, --packetsizes PACKETSIZES
                        Specify here the required packetsize! In case of more than one, just create a comma separated list such as 64,112,42. Default: 64
  -n NUM, --num NUM     Specify the number of flows to create - Default: 100



