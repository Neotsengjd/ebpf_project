import socket

# 設定伺服器的 IP 和埠
HOST = socket.gethostname()  # 本地 IP
PORT = 12345        # 任意未被使用的埠

# 建立一個 TCP/IP socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))  # 綁定 IP 和埠
    s.listen()            # 開始監聽
    print(f"Server is listening on {HOST}:{PORT}")

    conn, addr = s.accept()  # 等待客戶端連接
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)  # 接收數據
            if not data:
                break
            print(f"Received: {data.decode('utf-8')}")
            conn.sendall(data)  # 把收到的數據再發送回去（回音）


