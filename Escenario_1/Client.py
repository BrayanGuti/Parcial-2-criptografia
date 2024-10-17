import hashlib
import socket
from Crypto.Cipher import Salsa20
import base64
from Diffie_Hellman import diffie_hellman_client as dh_client
from Diffie_Hellman import diffie_hellman_compute_shared_key_client as dh_compute_shared_key_client

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

def client_program():
    p = params["p"]
    host = '127.0.0.1'  # El mismo host que el servidor
    port = 5000  # Puerto debe coincidir con el del servidor

    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Fase 1: Intercambio de claves
    private_key_client, public_key_client = dh_client(params)
    client_socket.send(str(public_key_client).encode())  # Enviar clave pública al servidor
    public_key_server = int(client_socket.recv(1024).decode())
    print(f"Clave pública del servidor recibida: {public_key_server}")

    # Cálculo de la clave compartida y generación de la clave simétrica
    shared_key_client = dh_compute_shared_key_client(private_key_client, public_key_server, p)
    symmetric_key_client = generate_symmetric_key(shared_key_client)
    print(f"Clave simétrica de 32 bytes generada en el cliente: {symmetric_key_client.hex()}")

    # Fase 2: Comunicación entre servidor y cliente
    print("Comienza la conversación con el servidor (mensajes cifrados con Salsa20)...")
    while True:
        # Enviar mensaje al servidor
        client_message = input("Tu mensaje: ")
        encrypted = encrypt_message_salsa20(symmetric_key_client, client_message)

        client_socket.send(encrypted.encode())  # Enviar mensaje encriptado al servidor
        if client_message.lower() == 'salir':
            break

        # Recibir respuesta del servidor
        server_message = client_socket.recv(1024).decode()
        decrypted_data = decrypt_message_salsa20(symmetric_key_client, server_message)  # Desencriptar mensaje
        
        print(f"Mensaje del servidor: {decrypted_data}")
        if decrypted_data.lower() == 'salir':
            break

    client_socket.close()  # Cerrar la conexión


# Función para encriptar un mensaje usando Salsa20
def encrypt_message_salsa20(key, message):
    cipher = Salsa20.new(key=key)  # No necesitas volver a codificar la clave, ya está en formato bytes
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
    client_program()
