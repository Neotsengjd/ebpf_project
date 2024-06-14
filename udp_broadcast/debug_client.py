import socket
import struct

# Establish a connection to the server
s = socket.socket()
host = socket.gethostname()  # Server's hostname or IP address
port = 12345  # The same port as used by the server
s.connect((host, port))
# Receive the payload from the server
data = s.recv(1024)  # Adjust size as needed based on the expected number of clients

# Magic number and initial byte
magic_number = data[:5]  # First 5 bytes for the magic number
if magic_number.decode() != "59123":
    print("Invalid magic number received.")
    s.close()
    exit()

data = data[5:]  # Remove the magic number from the data

# Decode the client list
clients = []
while len(data) >= 6:  # Each IP and port pair is 6 bytes long
    ip_packed = data[:4]
    port_packed = data[4:6]
    ip_address = socket.inet_ntoa(ip_packed)  # Convert 4-byte IP to human-readable format
    port, = struct.unpack('!H', port_packed)  # Unpack the 2-byte port number
    clients.append((ip_address, port))
    data = data[6:]  # Move to the next client in the list

# Print out the decoded clients
for client in clients:
    print("Client IP:", client[0], "Port:", client[1])

# Close the socket when done
s.close()
