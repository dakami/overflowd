from scapy.all import *
import struct, sys
from random import SystemRandom

sr = SystemRandom()
def r(): return sr.random()

p = rdpcap(sys.argv[1], 1000)


SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48




def parsenf(buf):
	(version, count) = struct.unpack('!HH',buf[0:4])
	if version != 5:
		print "Not NetFlow v5!"
		return

	# It's pretty unlikely you'll ever see more then 1000 records in a 1500 byte UDP packet
	if count <= 0 or count >= 1000:
		print "Invalid count %s" % count
		return

	uptime = socket.ntohl(struct.unpack('I',buf[4:8])[0])
	epochseconds = socket.ntohl(struct.unpack('I',buf[8:12])[0])

	seen=[]
	for i in range(0, count):
		try:
			base = SIZE_OF_HEADER+(i*SIZE_OF_RECORD)
			
			data = struct.unpack('!HHIIIIHHBBBBHH',buf[base+12:base+44])

			nfdata = {}
			nfdata['saddr'] = inet_ntoa(buf[base+0:base+4])
			nfdata['daddr'] = inet_ntoa(buf[base+4:base+8])
			nfdata['naddr'] = inet_ntoa(buf[base+8:base+12])
			c=0
			nfdata['inputidx'] = data[c]; c+=1;
			nfdata['outputidx'] = data[c]; c+=1;
			nfdata['pcount'] = data[c]; c+=1;
			nfdata['bcount'] = data[c]; c+=1;
			nfdata['stime'] = data[c]; c+=1;
			nfdata['etime'] = data[c]; c+=1;
			nfdata['sport'] = data[c]; c+=1;
			nfdata['dport'] = data[c]; c+=2;
			nfdata['flags'] = data[c]; c+=1;
			nfdata['protocol'] = data[c]; c+=1;
			nfdata['tos'] = data[c]; c+=1;
			nfdata['sasid'] = data[c]; c+=1;
			nfdata['dasid'] = data[c]; c+=1;
			seen.append(nfdata)
		except Exception as e:
			print e.args
			pass

	return seen
	#print "%s:%s -> %s:%s" % (nfdata['saddr'],nfdata['sport'],nfdata['daddr'],nfdata['dport'])

for packet in p:
   ip = packet['IP']
   seen = parsenf(packet['Raw'].load)
   for s in seen:
      if r()<0.001: 
      	s['raddr'] = ip.src
      	print s
