import socket

# 設定伺服器的 IP 和埠
HOST = socket.gethostname()  # 伺服器的 IP 地址
PORT = 12346        # 伺服器的埠

# 建立一個 TCP/IP socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))  # 連接到伺服器
    s.sendall(b'Hello, server')  # 發送數據
    data = s.recv(1024)  # 接收數據

print(f"Received: {data.decode('utf-8')}")

