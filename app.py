import socket
print("DANFERGRA")

hostname= socket.gethostname()
print(f"Hostname:{hostname}")

ipaddress=socket.gethostbyname(hostname)
print(f"ip addres: {ipaddress}")

while True:
    print("Hola")
    break

#git checkout -b feature/multiplicacion ||| te menea la rama para que no le pase nada 
#si me quere ver la rama el comando es | git branch la del asterisco es la mera wena
#

n1=int(input("dame 1 numero: "))
n2=int(input("Dame otro num: "))
print(n1+n2)

print("resta", n1-n2)

#git commit --amend -m "feat:funcion resta"
#git merge feat/suma ||| como guardar. ps asi
