from bcc import BPF
import pyroute2

# 加载 BPF 程序
bpf = BPF(src_file="tc_xdp.bpf.c")
try:
    fn = bpf.load_func("xdp_prog", BPF.XDP)
except Exception as e:
    print("Failed to load XDP program:", e)
    exit(1)

ip = pyroute2.IPRoute()
ipdb = pyroute2.IPDB(nl=ip)

# 使用支持 XDP 的实际接口，例如 eth0
idx = ipdb.interfaces["eth0"].index  # 修改为实际的接口名

# 确保没有 clsact 冲突
try:
    ip.tc("del", "clsact", idx)
except Exception as e:
    print("Failed to delete existing clsact:", e)

# 添加 clsact qdisc
try:
    ip.tc("add", "clsact", idx)
except Exception as e:
    print("Failed to add clsact qdisc:", e)
    exit(1)

# 添加过滤器
try:
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent=0xffff0000, classid=1, direct_action=True)  # 使用 0xffff0000 表示 ingress
    print("BPF XDP functionality: OK")
except Exception as e:
    print("Failed to add BPF filter:", e)

