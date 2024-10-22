import socket
import struct
import threading

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建 socket 对象
host ='127.0.0.1'  # 获取本地主机名
port = 12345  # 设置端口
s.bind((host, port))  # 绑定端口
s.listen(5)  # 等待客户端连接

clients = []
print("listening on ", host)

def handle(client):
    while True:
        try:
            client.c.recv(1024)
        except Exception as e:
        # This block handles any other exceptions
            print("An unexpected error occurred:", e)
            print("close " + client.addr[0] + ":" + str(client.addr[1]))
            clients.remove(client)
            client.c.close()
            break

class BPFClient:
    def __init__(self, c, addr):
        self.addr = addr
        self.c = c

magic_number = "59123"
while True:
    c, addr = s.accept()  # 建立客户端连接
    print('连接地址：', addr)
    #print(len(clients))
    #k = len(clients).to_bytes(1, 'big')
    #print(k)
    #b = int.from_bytes(k, 'big')
    #print(f"============={b}")
    
    payload = magic_number.encode() + b"b" + len(clients).to_bytes(1, 'big')
    #print(f"payload before packed: {payload}")
    #b = int.from_bytes(payload, 'big')
    #print(b)
    for client in clients:
        client_ip_packed = socket.inet_aton(client.addr[0])
        client_port_packed = addr[1].to_bytes(2,'big')
        payload += (client_ip_packed + client_port_packed)
    c.send(payload)
    print(payload)
    #print(f"payload[0]: {payload[0]}")
    #print(int.from_bytes(payload[0], 'big'))
    client = BPFClient(c, addr)
    clients.append(client)
    # Start thread to handle client
    thread = threading.Thread(target=handle, args=(client,))
    thread.start()
