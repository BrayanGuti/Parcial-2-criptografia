import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


def client_program():
    host = '172.20.10.4'  # Cambiado a localhost para ejecutar en la misma máquina
    port = 5000  # Número de puerto del servidor

    client_socket = socket.socket()  # Instanciar socket
    client_socket.connect((host, port))  # Conectar al servidor
    key = 'clave_secreta_muy_segura_de_256_'  # Clave de 16 bytes
    message = input(" -> ")  # Tomar entrada del usuario

    while message.lower().strip() != 'bye':
        encrypted = encrypt_message(key, message)
        client_socket.send(encrypted.encode())  # Enviar mensaje
        data = client_socket.recv(1024).decode()  # Recibir respuesta

        decrypt_data = decrypt_message(key, data) # Desencriptar mensaje
        print('Recibido del servidor: ' + decrypt_data)  # Mostrar en terminal

        message = input(" -> ")  # Volver a tomar entrada

    client_socket.close()  # Cerrar la conexión



# Función para encriptar un mensaje
def encrypt_message(key, message):
    # Convertir la clave a bytes si es necesario
    key = key.encode('utf-8')
    
    # Generar un vector de inicialización (IV) de 16 bytes
    iv = b'1234567890123456'  # IV fijo de 16 bytes (no recomendado en producción)
    
    # Crear el cifrador AES en modo CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad del mensaje para que sea múltiplo de 16 bytes
    padded_message = pad(message.encode(), AES.block_size)
    
    # Encriptar el mensaje
    encrypted_message = cipher.encrypt(padded_message)
    
    # Combinar IV y mensaje encriptado
    return base64.b64encode(iv + encrypted_message).decode('utf-8')

# Función para desencriptar un mensaje
def decrypt_message(key, encrypted_message):
    # Convertir la clave a bytes si es necesario
    key = key.encode('utf-8')
    
    # Decodificar el mensaje en base64
    encrypted_message = base64.b64decode(encrypted_message)
    
    # Separar el IV de los datos encriptados
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    
    # Crear el descifrador AES en modo CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Desencriptar y despadear el mensaje
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    
    return decrypted_message.decode('utf-8')


if __name__ == '__main__':
    client_program()

