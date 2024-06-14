import socket
import struct
import threading

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建 socket 对象
host =  socket.gethostname()
port = 12345  # 设置端口
s.bind((host, port))  # 绑定端口

clients = []
print("listening on ", host)



class BPFClient:
    def __init__(self, addr):
        self.addr = addr

magic_number = "59123"
while True:
    indata, addr = s.recvfrom(1024)
    print('recvfrom ' + str(addr) + ': ' + indata.decode())
    print('连接地址：', addr)
    print('bytes：', addr[0], ":", addr[1])
    
    client = BPFClient(addr)
    clients.append(client)
    payload = magic_number.encode() + b"b" + len(clients).to_bytes(1, 'big')

    for client in clients:
        client_ip_packed = socket.inet_aton(client.addr[0])
        client_port_packed = client.addr[1].to_bytes(2, 'big')
        payload += (client_ip_packed + client_port_packed)
    s.sendto(payload+b'\x00', addr)
