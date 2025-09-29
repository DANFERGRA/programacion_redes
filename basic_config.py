import serial
import time

def configure_device(port, baudrate, hostname, username, password, domain):
    try:
        # Abrir conexión serial
        ser = serial.Serial(port, baudrate, timeout=1)
        time.sleep(2)  # Esperar que inicie la conexión

        # Entrar al modo privilegiado y configuración
        ser.write("enable\r\n".encode())
        time.sleep(1)
        ser.write("configure terminal\r\n".encode())
        time.sleep(1)

        # Configuración básica
        ser.write(f"hostname {hostname}\r\n".encode())
        time.sleep(1)
        ser.write(f"username {username} privilege 15 secret {password}\r\n".encode())
        time.sleep(1)
        ser.write(f"ip domain-name {domain}\r\n".encode())
        time.sleep(1)

        # Generación de llaves SSH
        ser.write("crypto key generate rsa modulus 1024\r\n".encode())
        time.sleep(5)  # este proceso tarda más

        # Configuración de acceso remoto
        ser.write("line vty 0 4\r\n".encode())
        time.sleep(1)
        ser.write("login local\r\n".encode())
        ser.write("transport input ssh\r\n".encode())
        ser.write("transport output ssh\r\n".encode())
        ser.write("exit\r\n".encode())

        # Línea de consola
        ser.write("line console 0\r\n".encode())
        time.sleep(1)

        # Cerrar sesión
        ser.write("end\r\n".encode())
        ser.write("write memory\r\n".encode())  # guardar config
        ser.close()

        print("Device configured successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")

r1= configure_device("COM3", 9600, "Router1", "cisco", "cisco", "example.com")