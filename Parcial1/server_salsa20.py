import socket
import threading
from Crypto.Cipher import Salsa20
import base64

def handle_client(conn):
    # Recibir la clave sin cifrar del cliente
    key = conn.recv(1024).decode()  
    print(f"Clave recibida del cliente: '{key}'")
    
    while True:
        data = conn.recv(1024).decode()  # Recibir datos del cliente
        if not data:
            break
        decrypt_msg = decrypt_message_salsa20(key, data)
        print("De usuario conectado: " + decrypt_msg)
        response = input(' -> ')  # Pedir mensaje de respuesta
        encrypt_response = encrypt_message_salsa20(key, response)
        conn.send(encrypt_response.encode())  # Enviar respuesta cifrada

    conn.close()  # Cerrar la conexión con el cliente actual


def server_program():
    host = '0.0.0.0'  # Dirección de host
    port = 5000  # Puerto a usar

    server_socket = socket.socket()  
    server_socket.bind((host, port))  
    server_socket.listen(2)  # Escucha hasta 2 clientes

    print(f"Servidor escuchando en {host}:{port}")

    while True:
        conn, address = server_socket.accept()  # Acepta nueva conexión
        print("Conexión desde: " + str(address))
        
        # Crear un hilo para manejar la conexión del cliente
        client_thread = threading.Thread(target=handle_client, args=(conn,))
        client_thread.start()


# Función para encriptar un mensaje usando Salsa20
def encrypt_message_salsa20(key, message):
    key = key.encode('utf-8')
    cipher = Salsa20.new(key=key)
    nonce = cipher.nonce
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(nonce + encrypted_message).decode('utf-8')


# Función para desencriptar un mensaje usando Salsa20
def decrypt_message_salsa20(key, encrypted_message):
    key = key.encode('utf-8')
    encrypted_message = base64.b64decode(encrypted_message)
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    cipher = Salsa20.new(key=key, nonce=nonce)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message.decode('utf-8')


if __name__ == '__main__':
    server_program()
