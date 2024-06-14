from bcc import BPF
import  pyroute2




bpf = BPF(src_file="tc.bpf.c")


fn = bpf.load_func("socket_filter", BPF.SCHED_CLS)


ip = pyroute2.IPRoute()
ipdb = pyroute2.IPDB(nl=ip)
idx = ipdb.interfaces["lo"].index
ip.tc("add", "clsact", idx)
#ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
#      parent="ffff:fff2", classid=1, direct_action=True)
ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
      parent="ffff:fff3", classid=1, direct_action=True)

print("BPF tc functionality - SCHED_CLS: OK")

