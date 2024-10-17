import socket
from Crypto.Cipher import Salsa20
import base64

def client_program():
    host = '192.168.1.5'  # Dirección del servidor
    port = 5000  # Puerto del servidor

    client_socket = socket.socket()  # Instanciar socket
    client_socket.connect((host, port))  # Conectar al servidor
    key = 'clave_secreta_muy_segura_de_256_'  # Clave de 32 bytes (para Salsa20)

    # Enviar la clave sin cifrar al servidor
    client_socket.send(key.encode())  
    print(f"Clave '{key}' enviada al servidor.")

    message = input(" -> ")  # Tomar entrada del usuario

    while message.lower().strip() != 'bye':
        encrypted = encrypt_message_salsa20(key, message)
        client_socket.send(encrypted.encode())  # Enviar mensaje cifrado
        data = client_socket.recv(1024).decode()  # Recibir respuesta

        decrypt_data = decrypt_message_salsa20(key, data)  # Desencriptar mensaje
        print('Recibido del servidor: ' + decrypt_data)  # Mostrar en terminal

        message = input(" -> ")  # Volver a tomar entrada

    client_socket.close()  # Cerrar la conexión


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
    client_program()
