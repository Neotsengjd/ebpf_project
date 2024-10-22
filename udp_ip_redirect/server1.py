import socket
import struct
import threading

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建 socket 对象
host =  '127.0.0.1'
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

    payload = magic_number.encode() + b"b" + len(clients).to_bytes(1, 'big')
    for client in clients:
        client_ip_packed = socket.inet_aton(client.addr[0])
        client_port_packed = socket.htons(client.addr[1]).to_bytes(2, byteorder='big')
        payload += (client_ip_packed + client_port_packed)
    client = BPFClient(addr)
    clients.append(client)
    s.sendto(payload+b"0",  clients[0].addr)
