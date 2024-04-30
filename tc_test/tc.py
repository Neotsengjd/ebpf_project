#!/usr/bin/python3
from bcc import BPF
import socket
import os
from time import sleep
from pyroute2 import IPRoute

b = BPF(src_file="tc.bpf.c")

ipr = IPRoute()
links = ipr.link_lookup(ifname="lo")
idx = links[0]

try:
    ipr.tc("add", "ingress", idx, "ffff:")
except:
    print("qdisc ingress already exists")

# TC. Choose one program: drop all packets, just drop ping requests, or respond
# to ping requests
# fi = b.load_func("tc_drop", BPF.SCHED_CLS)
# fi = b.load_func("tc_drop_ping", BPF.SCHED_CLS)
fi = b.load_func("socket_filter", BPF.SCHED_CLS)

ipr.tc("add-filter", "bpf", idx, ":1", fd=fi.fd,
        name=fi.name, parent="ffff:", action="ok", classid=1, da=True)




