# Overflowd
Overflowd (Traffic Intelligence Distribution Engine)

# TL;DR:

Netflow to those suffering from network flows:  Proactively delivering anti-spoof and contact data.

# Quick Start
    # ./overflowd.py -h
    Usage: 
    Overflowd (Traffic Intelligence Distribution Engine)
    Dan Kaminsky, Chief Scientist, whiteops.com
    with:  Cosmo Mielke and Jeff Ward
    
    Options:
      -h, --help            show this help message and exit
      -f PCAPFILE, --pcapfile=PCAPFILE
                            Load from PCAP
      -u UDPPORT, --udpport=UDPPORT
                            Stream from UDP (7777)
      -r RATE, --rate=RATE  Odds flow will be reported scaled by packet count
                            (0.000001) 
                            
    # ./overflowd.py -f  netflow_4M.pcap  | head 
    {'flowdata': {'data': {'bcount': 682512, 'protocol': 6, 'tos': 0, 'etime': 1325314888, 'daddr': '122.166.77.74', 'pcount': 17001, 'flags': 16, 'stime': 1325252876, 'saddr': '122.166.82.196', 'dport': 20999, 'sport': 4568}, 'sourcetype': {'version': 5, 'type': 'Netflow'}}, 'signature': {'key': 'd52b9644ba6ffd2bdaa6505e649fd80ca80fad72baf2f46f5c83ab8a2a354df3', 'signature': 'z5yMEHH0pYe++uOiNhWzLkCyXsTQiMokNMZ3AWi8v8+0cuTy6ScCPS/RB0PXDCprmPLaC0AJpFCEW9S5bbB7CHsiZmxvd2RhdGEiOiB7ImRhdGEiOiB7ImJjb3VudCI6IDY4MjUxMiwgInByb3RvY29sIjogNiwgInRvcyI6IDAsICJldGltZSI6IDEzMjUzMTQ4ODgsICJkYWRkciI6ICIxMjIuMTY2Ljc3Ljc0IiwgInBjb3VudCI6IDE3MDAxLCAiZmxhZ3MiOiAxNiwgInN0aW1lIjogMTMyNTI1Mjg3NiwgInNhZGRyIjogIjEyMi4xNjYuODIuMTk2IiwgImRwb3J0IjogMjA5OTksICJzcG9ydCI6IDQ1Njh9LCAic291cmNldHlwZSI6IHsidmVyc2lvbiI6IDUsICJ0eXBlIjogIk5ldGZsb3cifX0sICJtZXRhZGF0YSI6IHsiaW5mbyI6ICJGTE9XU0VFTiIsICJjbGFzcyI6ICJJTkZPUk1BVElPTkFMIiwgInRpbWUiOiAxNDc3Nzc4MDI3LjEzODEwOX19'}, 'metadata': {'info': 'FLOWSEEN', 'class': 'INFORMATIONAL', 'time': 1477778027.138109}}
    {'flowdata': {'data': {'bcount': 1395502, 'protocol': 6, 'tos': 0, 'etime': 1325838753, 'daddr': '122.166.251.246', 'pcount': 6130, 'flags': 0, 'stime': 1325834529, 'saddr': '122.166.218.109', 'dport': 445, 'sport': 3183}, 'sourcetype': {'version': 5, 'type': 'Netflow'}}, 'signature': {'key': 'd52b9644ba6ffd2bdaa6505e649fd80ca80fad72baf2f46f5c83ab8a2a354df3', 'signature': '2MVQ2fhHpeC83cE3Dt1wK08z9/dxK19PNj7P7I4yCno1zMtw1qTvLH45sTXWsCicT7bo8DF0Uj1HeJ4gDPLiCHsiZmxvd2RhdGEiOiB7ImRhdGEiOiB7ImJjb3VudCI6IDEzOTU1MDIsICJwcm90b2NvbCI6IDYsICJ0b3MiOiAwLCAiZXRpbWUiOiAxMzI1ODM4NzUzLCAiZGFkZHIiOiAiMTIyLjE2Ni4yNTEuMjQ2IiwgInBjb3VudCI6IDYxMzAsICJmbGFncyI6IDAsICJzdGltZSI6IDEzMjU4MzQ1MjksICJzYWRkciI6ICIxMjIuMTY2LjIxOC4xMDkiLCAiZHBvcnQiOiA0NDUsICJzcG9ydCI6IDMxODN9LCAic291cmNldHlwZSI6IHsidmVyc2lvbiI6IDUsICJ0eXBlIjogIk5ldGZsb3cifX0sICJtZXRhZGF0YSI6IHsiaW5mbyI6ICJGTE9XU0VFTiIsICJjbGFzcyI6ICJJTkZPUk1BVElPTkFMIiwgInRpbWUiOiAxNDc3Nzc4MDI3LjE4MTE2OH19'}, 'metadata': {'info': 'FLOWSEEN', 'class': 'INFORMATIONAL', 'time': 1477778027.181168}}
    {'flowdata': {'data': {'bcount': 17227833, 'protocol': 6, 'tos': 0, 'etime': 1325317896, 'daddr': '122.166.80.208', 'pcount': 15726, 'flags': 24, 'stime': 1325257892, 'saddr': '122.166.72.234', 'dport': 1227, 'sport': 139}, 'sourcetype': {'version': 5, 'type': 'Netflow'}}, 'signature': {'key': 'd52b9644ba6ffd2bdaa6505e649fd80ca80fad72baf2f46f5c83ab8a2a354df3', 'signature': 'brw1G8hurkaLEFhWCrRnW0uM/kEPeoeBWDdkLeveIefuUzxPO30UHhRMSynrMAyam9tPWi0xudNrEjF8/LTwD3siZmxvd2RhdGEiOiB7ImRhdGEiOiB7ImJjb3VudCI6IDE3MjI3ODMzLCAicHJvdG9jb2wiOiA2LCAidG9zIjogMCwgImV0aW1lIjogMTMyNTMxNzg5NiwgImRhZGRyIjogIjEyMi4xNjYuODAuMjA4IiwgInBjb3VudCI6IDE1NzI2LCAiZmxhZ3MiOiAyNCwgInN0aW1lIjogMTMyNTI1Nzg5MiwgInNhZGRyIjogIjEyMi4xNjYuNzIuMjM0IiwgImRwb3J0IjogMTIyNywgInNwb3J0IjogMTM5fSwgInNvdXJjZXR5cGUiOiB7InZlcnNpb24iOiA1LCAidHlwZSI6ICJOZXRmbG93In19LCAibWV0YWRhdGEiOiB7ImluZm8iOiAiRkxPV1NFRU4iLCAiY2xhc3MiOiAiSU5GT1JNQVRJT05BTCIsICJ0aW1lIjogMTQ3Nzc3ODAyNy4yNTU3NTJ9fQ=='}, 'metadata': {'info': 'FLOWSEEN', 'class': 'INFORMATIONAL', 'time': 1477778027.255752}}
    {'flowdata': {'data': {'bcount': 63671628, 'protocol': 47, 'tos': 0, 'etime': 1325317896, 'daddr': '122.166.14.93', 'pcount': 60572, 'flags': 16, 'stime': 1325255892, 'saddr': '3.138.170.99', 'dport': 0, 'sport': 0}, 'sourcetype': {'version': 5, 'type': 'Netflow'}}, 'signature': {'key': 'd52b9644ba6ffd2bdaa6505e649fd80ca80fad72baf2f46f5c83ab8a2a354df3', 'signature': '0eCPikLp4ywGUlvdHs/b+dFOgDdBbGuWUIdLD3tkZ5a3iGvW6pOodmtMSMpQFVfST03db+ZzfMCL0HcuGesxAXsiZmxvd2RhdGEiOiB7ImRhdGEiOiB7ImJjb3VudCI6IDYzNjcxNjI4LCAicHJvdG9jb2wiOiA0NywgInRvcyI6IDAsICJldGltZSI6IDEzMjUzMTc4OTYsICJkYWRkciI6ICIxMjIuMTY2LjE0LjkzIiwgInBjb3VudCI6IDYwNTcyLCAiZmxhZ3MiOiAxNiwgInN0aW1lIjogMTMyNTI1NTg5MiwgInNhZGRyIjogIjMuMTM4LjE3MC45OSIsICJkcG9ydCI6IDAsICJzcG9ydCI6IDB9LCAic291cmNldHlwZSI6IHsidmVyc2lvbiI6IDUsICJ0eXBlIjogIk5ldGZsb3cifX0sICJtZXRhZGF0YSI6IHsiaW5mbyI6ICJGTE9XU0VFTiIsICJjbGFzcyI6ICJJTkZPUk1BVElPTkFMIiwgInRpbWUiOiAxNDc3Nzc4MDI3LjI1NjE1M319'}, 'metadata': {'info': 'FLOWSEEN', 'class': 'INFORMATIONAL', 'time': 1477778027.256153}}

# What's going on here

Our networks are increasingly under attack, we don't always quite know from
where, and even if so, who do we talk to?  Abuse management is *hard*, just in
terms of a communications coordination problem.  Can we make it easier?

What if potentially malicious network traffic arrived with tracing data, not
just from the networks attacking us (who might *ahem* might not be too
communicative) but from all the networks bringing us their noise?

It would require all the networks in the middle to have monitoring frameworks.
Well, they do.  Everyone's running some protocol that ends in "flow".  But the
data from Netflow, SFlow, QFlow, etc. either goes to local analysts, or
giant overcentralized data pits.  What if, one out of a million packets
caused a tracer message to go to the source and destination of traffic?

Purely through stochastic dynamics, you'd end up with metadata -- the nastier
the flood, the faster the context would arrive.  And you wouldn't need everyone
to deploy all at once (which is good because this is a thing that does not
happen).  Over time, more participants, better data distribution.  Some 
participants, some data distribution.

It'd certainly be easier to trace spoofed flows, manage asymmetric routing
issues (traceroute is pleasantly naive), and honestly, just figure out who to
talk to.

And we could potentially send traffic with more frequency, if we had 
strong reason to believe a particular flow was sketchy.

Think of this as a much more distributed Netflow.  Privacy issues aren't 
really there; either you're receiving data you already know (since
metadata follows the path of the original flows) or that you want to know
(that somebody is spoofing traffic as you, and roughly, here's from where).

This is experimental work on one of the more annoying, and difficult tasks
we have maintaining the Internet.  We can do do better than this particular
version of Overflowd, but it's a good place to start a conversation.


# Notes

1. Netflow data from https://traces.simpleweb.org/traces/netflow/
2. Key management eventually works out through some formal mechanism, but
just having a consistent key, that's used in quantity, over time, over
many networks is its own mechanism.

# TODO

1. Actually send updates.  Starting with 65535/udp, then HTTP/HTTPS to source
and dest.
2. Persist signing key, create encryption mode