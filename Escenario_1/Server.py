import socket
import threading
import hashlib
from Diffie_Hellman import diffie_hellman_server as dh_server
from Diffie_Hellman import diffie_hellman_compute_shared_key_server as dh_compute_shared_key_server
from Crypto.Cipher import Salsa20
import base64

# Establecer los parámetros para el protocolo Diffie-Hellman
# Utilizando valores grandes para p, q y g, que son primordiales en la seguridad del intercambio de claves.
# Estos valores corresponden a:
# - p: Un número primo grande, usado como módulo en las operaciones
# - q: Un subgrupo primo (factor de p-1), utilizado en el cálculo de claves privadas
# - g: Un generador del grupo multiplicativo mod p, que permite calcular las claves públicas

params = {
    "p": 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903,
    "q": 68632250537247590640277566336950965661666082362407566658763297813768761281033511494801849527294240194886539508280661671738527174668225804642485574079640362414564265776135160634228884760021428072214941538991845905600826715068688459980034484995253710718979231273945712971512652905080032662072960876614367641951,
    "g": 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579
}

def generate_symmetric_key(shared_key):
    # Convertir la clave compartida en un string y aplicar SHA-256 para generar una clave de 32 bytes
    shared_key_bytes = str(shared_key).encode()
    return hashlib.sha256(shared_key_bytes).digest()

def handle_client(conn):
    private_key_server, public_key_server = dh_server(params)
    p = params["p"]

    # Fase 1: Intercambio de claves
    public_key_client = int(conn.recv(1024).decode())
    print(f"Clave pública del cliente recibida: {public_key_client}")
    conn.send(str(public_key_server).encode())  # Enviar clave pública del servidor
    print(f"Clave pública del servidor enviada: {public_key_server}")

    # Cálculo de la clave compartida y generación de la clave simétrica
    shared_key_server = dh_compute_shared_key_server(private_key_server, public_key_client, p)
    symmetric_key_server = generate_symmetric_key(shared_key_server)
    print(f"Clave compartida calculada en el servidor: {shared_key_server}")
    print(f"Clave simétrica de 32 bytes generada en el servidor: {symmetric_key_server.hex()}")

    # Fase 2: Comunicación entre servidor y cliente
    print("Comenzando conversación con el cliente (mensajes cifrados con Salsa20)...")
    while True:
        # Recibir mensaje del cliente
        client_message = conn.recv(1024).decode()
        decrypted_data = decrypt_message_salsa20(symmetric_key_server, client_message)  # Desencriptar mensaje

        if decrypted_data.lower() == 'salir':
            print("El cliente ha terminado la conexión.")
            break
        print(f"Mensaje del cliente: {decrypted_data}")

        # Enviar respuesta al cliente
        server_message = input("Tu mensaje: ")
        encrypted = encrypt_message_salsa20(symmetric_key_server, server_message)

        conn.send(encrypted.encode())
        if server_message.lower() == 'salir':
            print("Terminando la conexión con el cliente.")
            break

    conn.close()  # Cerrar la conexión con el cliente actual

def server_program():
    host = '127.0.0.1'  # Dirección del host
    port = 5000  # Puerto a usar

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)  # Escuchar hasta 2 conexiones

    print(f"Servidor escuchando en {host}:{port}")

    while True:
        conn, address = server_socket.accept()  # Aceptar nueva conexión
        print("Conexión desde: " + str(address))
        
        # Crear un hilo para manejar la conexión del cliente
        client_thread = threading.Thread(target=handle_client, args=(conn,))
        client_thread.start()

# Función para encriptar un mensaje usando Salsa20
def encrypt_message_salsa20(key, message):
    # La clave ya está en formato bytes, no necesitas codificarla a UTF-8
    cipher = Salsa20.new(key=key)
    nonce = cipher.nonce
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(nonce + encrypted_message).decode('utf-8')


# Función para desencriptar un mensaje usando Salsa20
def decrypt_message_salsa20(key, encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message)
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    cipher = Salsa20.new(key=key, nonce=nonce)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message.decode('utf-8')


if __name__ == '__main__':
    server_program()
