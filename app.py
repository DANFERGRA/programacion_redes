import socket
print("DANFERGRA")

hostname= socket.gethostname()
print(f"Hostname:{hostname}")

ipaddress=socket.gethostbyname(hostname)
print(f"ip addres: {ipaddress}")

while True:
    print("Hola"