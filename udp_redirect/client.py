import socket

HOST = '127.0.0.1'
PORT = 12346
server_addr = (HOST, PORT)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

outdata = "hi"
print('sendto ' + str(server_addr) + ': ' + outdata)
s.sendto(outdata.encode(), server_addr)
    
while True:
    indata, addr = s.recvfrom(1024)
    print('recv' + str(indata))
