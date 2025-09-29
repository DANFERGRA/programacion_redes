import serial
import time

class RouterCisco:
    def __init__(self, puerto, baudios=9600, timeout=1):
        """
        Inicializa la conexión serial con el router Cisco.
        """
        self.puerto = puerto
        self.baudios = baudios
        self.timeout = timeout
        self.conexion = None

    def conectar(self):
        """
        Abre la conexión serial al router.
        """
        try:
            self.conexion = serial.Serial(port=self.puerto, baudrate=self.baudios, timeout=self.timeout)
            time.sleep(2)  # Espera para inicializar la consola
            print(f"[+] Conectado correctamente al router por {self.puerto} a {self.baudios} bps.")
        except serial.SerialException as e:
            print(f"[!] Error al conectar: {e}")
            self.conexion = None

    def enviar_comando(self, comando, espera=1):
        """
        Envía cualquier comando al router y retorna la salida.
        """
        if self.conexion is None:
            print("[!] No hay conexión activa.")
            return None
        
        # Enviar comando
        self.conexion.write((comando + '\n').encode())
        time.sleep(espera)  # Esperar a que el router responda
        
        # Leer toda la respuesta disponible
        salida = self.conexion.read_all().decode(errors='ignore')
        return salida

    def cerrar(self):
        """
        Cierra la conexión serial.
        """
        if self.conexion:
            self.conexion.close()
            print("[+] Conexión cerrada.")

if __name__ == "__main__":
    puerto = 'COM9' \
    ''  # Cambia según tu puerto
    router = RouterCisco(puerto)
    router.conectar()
    
    if router.conexion:
        try:
            while True:
                comando = input("Ingrese comando para el router (use 'quit' para salir del programa): ")
                if comando.lower() == 'quit':  # Solo 'quit' cierra el script
                    print("[*] Saliendo del programa...")
                    break
                # Envía cualquier comando, incluyendo 'exit', al router
                respuesta = router.enviar_comando(comando)
                print(respuesta)
        except KeyboardInterrupt:
            print("\n[*] Se interrumpió la ejecución con Ctrl+C.")
        finally:
            router.cerrar()
