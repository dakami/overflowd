# stoched
Stochastic Traffic Factoring Utility (Daemon)

# Quick Start

    # python stoched.py ./netflow_mini.pcap.gz 100 | head
    {'sasid': 0, 'bcount': 48, 'raddr': '122.166.4.242', 'protocol': 6, 'inputidx': 111, 'tos': 0, 'etime': 1811402026, 'daddr': '122.221.180.200', 'pcount': 1, 'flags': 0, 'stime': 1811402026, 'naddr': '99.145.4.143', 'saddr': '122.166.218.170', 'dport': 2967, 'outputidx': 120, 'sport': 3062, 'dasid': 0}
    {'sasid': 0, 'bcount': 93, 'raddr': '122.166.4.242', 'protocol': 17, 'inputidx': 120, 'tos': 0, 'etime': 1811402154, 'daddr': '122.166.170.25', 'pcount': 1, 'flags': 0, 'stime': 1811402154, 'naddr': '122.166.170.25', 'saddr': '205.208.49.208', 'dport': 12855, 'outputidx': 116, 'sport': 50794, 'dasid': 0}
    {'sasid': 0, 'bcount': 161, 'raddr': '122.166.4.242', 'protocol': 17, 'inputidx': 120, 'tos': 0, 'etime': 1811402604, 'daddr': '122.166.170.142', 'pcount': 1, 'flags': 0, 'stime': 1811402604, 'naddr': '122.166.170.142', 'saddr': '120.189.7.148', 'dport': 6876, 'outputidx': 116, 'sport': 22231, 'dasid': 0}
    {'sasid': 0, 'bcount': 25056, 'raddr': '122.166.4.242', 'protocol': 6, 'inputidx': 110, 'tos': 0, 'etime': 1811402857, 'daddr': '206.212.65.165', 'pcount': 25, 'flags': 0, 'stime': 1811401513, 'naddr': '99.145.4.143', 'saddr': '122.166.16.19', 'dport': 80, 'outputidx': 120, 'sport': 49356, 'dasid': 0}
    {'sasid': 0, 'bcount': 53, 'raddr': '122.166.4.242', 'protocol': 17, 'inputidx': 120, 'tos': 0, 'etime': 1811403113, 'daddr': '122.166.71.110', 'pcount': 1, 'flags': 0, 'stime': 1811403113, 'naddr': '122.166.71.110', 'saddr': '30.166.81.237', 'dport': 10822, 'outputidx': 108, 'sport': 22441, 'dasid': 0}
    {'sasid': 0, 'bcount': 11016, 'raddr': '122.166.4.242', 'protocol': 6, 'inputidx': 124, 'tos': 0, 'etime': 1811402988, 'daddr': '4.214.161.101', 'pcount': 10, 'flags': 0, 'stime': 1811398636, 'naddr': '99.145.4.143', 'saddr': '122.166.38.39', 'dport': 1761, 'outputidx': 120, 'sport': 13189, 'dasid': 0}
    {'sasid': 0, 'bcount': 806, 'raddr': '122.166.4.242', 'protocol': 6, 'inputidx': 116, 'tos': 0, 'etime': 1811402795, 'daddr': '20.56.88.217', 'pcount': 3, 'flags': 0, 'stime': 1811402603, 'naddr': '99.145.4.143', 'saddr': '122.166.174.62', 'dport': 80, 'outputidx': 120, 'sport': 1575, 'dasid': 0}
    
# Notes

1. Netflow data from https://traces.simpleweb.org/traces/netflow/
2. Basic architecture concept:
   1. My sense is we run this on netflow pcaps (that contain UDP streams of router pflows).
   2. We do basic emission of metadata, scaled by packet count, signed, with an attached signing key and an abuse contact.
   3. Maybe a severity field, "Informational", "Machine Suspected", "Human Suspected", "Human Confirmed / Trying To Remediate"
   4. Was originally thinking JSON over 65535/udp, but also a HTTP(S) to 80/tcp and 443/tcp 
   5. Sign with http://pynacl.readthedocs.io/en/latest/signing/ , just include the bare signing key in the payload for now
3. Should support more than netflow, should support more evidence that we are actually witnessing a flow, but this is about just PoC