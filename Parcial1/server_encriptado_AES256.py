import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def handle_client(conn):
    key = 'clave_secreta_muy_segura_de_256_'  # 16 bytes exactos    
    while True:
        data = conn.recv(1024).decode()  # Recibir datos del cliente
        if not data:
            break
        decrypt_msg = decrypt_message(key, str(data))
        print("De usuario conectado: " + str(decrypt_msg))
        response = input(' -> ')  # Pedir mensaje de respuesta
        encrypt_response = encrypt_message(key, response)
        conn.send(encrypt_response.encode())  # Enviar respuesta al cliente

    conn.close()  # Cerrar la conexión con el cliente actual

def server_program():
    host = '0.0.0.0'  # Obtiene el nombre del host
    port = 5000  # Puerto a usar

    server_socket = socket.socket()  
    server_socket.bind((host, port))  
    server_socket.listen(2)  # Escucha hasta 2 clientes simultáneamente

    print(f"Servidor escuchando en {host}:{port}")

    while True:
        conn, address = server_socket.accept()  # Acepta nueva conexión
        print("Conexión desde: " + str(address))
        
        # Crear un hilo para manejar la conexión del cliente
        client_thread = threading.Thread(target=handle_client, args=(conn,))
        client_thread.start()



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
    server_program()