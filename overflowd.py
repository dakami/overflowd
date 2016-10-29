#!/usr/bin/env python

import struct, sys
from random import SystemRandom

sr = SystemRandom()
def r(): return sr.random()
import dpkt, socket
from socket import inet_ntoa

import nacl.encoding
import nacl.signing

import json
from base64 import b64encode

import time
import optparse 
opts = None
remainder = None


signing_key = nacl.signing.SigningKey.generate()
verify_key_base64 = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)

def parsenf(buf):
    SIZE_OF_HEADER = 24
    SIZE_OF_RECORD = 48

    (version, count) = struct.unpack('!HH',buf[0:4])
    if version != 5:
        return []
    
    if count <= 0 or count >= 1000:
        return []
    
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
            #nfdata['naddr'] = inet_ntoa(buf[base+8:base+12])
            c=0
            #nfdata['inputidx'] = data[c];
            c+=1;
            #nfdata['outputidx'] = data[c];
            c+=1;
            nfdata['pcount'] = data[c]; c+=1;
            nfdata['bcount'] = data[c]; c+=1;
            nfdata['stime'] = data[c]; c+=1;
            nfdata['etime'] = data[c]; c+=1;
            nfdata['sport'] = data[c]; c+=1;
            nfdata['dport'] = data[c]; c+=2;
            nfdata['flags'] = data[c]; c+=1;
            nfdata['protocol'] = data[c]; c+=1;
            nfdata['tos'] = data[c]; c+=1;
            #nfdata['sasid'] = data[c];
            c+=1;
            #nfdata['dasid'] = data[c];
            c+=1;
            seen.append(nfdata)
        except Exception as e:
            #raise e
            pass
    
    return seen
	#print "%s:%s -> %s:%s" % (nfdata['saddr'],nfdata['sport'],nfdata['daddr'],nfdata['dport'])

def read_from_udp():
    port = 7777
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", port))
    while 1:
        data, addr = s.recvfrom(1500)
        try:
            seen_flows = parsenf(data)
            for sf in seen_flows:
                maybe_report(sf)
        except:
            raise


def read_from_pcap():
    """Open up a test pcap file and print out the packets"""
    with open(opts.pcapfile, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            try:
                seen_flows = parsenf(dpkt.ethernet.Ethernet(buf).ip.udp.data)
                for sf in seen_flows:
                    maybe_report(sf)
            except:
                raise

def maybe_report(sf):
    if(r() / float(sf['pcount']) > opts.rate): return
    report = {}
    flowdata = {}
    flowdata['sourcetype']={"type": "Netflow", "version": 5}
    flowdata['data']=sf
    report['flowdata']=flowdata
    contact = {}
    contact['email'] = "dan@whiteops.com"
    contact['identity'] = "White Ops"
    metadata = {}
    metadata['class'] = "INFORMATIONAL"
    metadata['info']  = "FLOWSEEN"
    metadata['time']  = time.time()
    report['metadata'] = metadata
    
    signature = {}
    signature['key'] = verify_key_base64
    signature['signature'] = b64encode(signing_key.sign(json.dumps(report)))
    report['signature']=signature
    
    notify(report)

def notify(report):
    # XXX TODO, send UDP, HTTP, HTTPS notifications
    # for now, just print
    print report

if __name__ == '__main__':
    usage ="""
Overflowd (Traffic Intelligence Distribution Engine)
Dan Kaminsky, Chief Scientist, whiteops.com
with:  Cosmo Mielke
       Jeff Ward
Options:
   -f pcapfile:   Load from PCAP       
   -u udpport:    Stream from UDP port (7777)
   -r [rate]:     Odds flow will be reported scaled by packet count (0.00001)

"""
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-f", "--pcapfile", dest="pcapfile", help="Load from PCAP")
    parser.add_option("-u", "--udpport",  dest="udpport", default=7777, help="Stream from UDP (7777)")
    parser.add_option("-r", "--rate",  dest="rate", default=0.00001, help="Odds flow will be reported scaled by packet count (0.000001)")
    opts, remainder = parser.parse_args(sys.argv)
    if opts.pcapfile:
        read_from_pcap()
    else:
        read_from_udp()
    
