import serial
import time

def configure_device(port, baudrate, com, hostname, username):
    try:
        serial_conn = serial.Serial(port, baudrate, timeout=1)
        time.sleep(2)  # Wait for the connection to establish
        serial_conn.write(com.encode())
        time.sleep(1)  # Wait for the command to be processed
        ser.write(f"hostname {hostname}\n".encode())
        time.sleep(1)
        ser.write(f"username {username} privilege 15 secret {username}\n".encode())
        time.sleep(1)
        serial_conn.close()
        print("Configuration applied successfully.")
    except serial.SerialException as e:
        print(f"Error: {e}")#git push origin feature/multiplicacion ||| para subir los cambios
