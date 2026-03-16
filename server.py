import socket


server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_sock.bind(("127.0.0.1", 7891))


server_sock.listen(10)
print("Server listening...")


client_sock, addr = server_sock.accept()
print(f"Connection from {addr}")


data = client_sock.recv(1024)
print("Received:", data.decode())


client_sock.send(b"Hello from server")


client_sock.close()
server_sock.close()
