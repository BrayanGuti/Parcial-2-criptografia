from Crypto.Cipher import Salsa20
import base64

# Función para encriptar un mensaje usando Salsa20
def encrypt_message_salsa20(key, message):
    # Convertir la clave a bytes (debe ser de 32 bytes para Salsa20)
    key = key.encode('utf-8')
    
    # Generar un nonce aleatorio de 8 bytes
    cipher = Salsa20.new(key=key)
    nonce = cipher.nonce
    
    # Cifrar el mensaje
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    
    # Devolver el mensaje cifrado junto con el nonce
    return base64.b64encode(nonce + encrypted_message).decode('utf-8')

# Función para desencriptar un mensaje usando Salsa20
def decrypt_message_salsa20(key, encrypted_message):
    # Convertir la clave a bytes
    key = key.encode('utf-8')
    
    # Decodificar el mensaje en base64
    encrypted_message = base64.b64decode(encrypted_message)
    
    # Extraer el nonce (los primeros 8 bytes)
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    
    # Crear el descifrador Salsa20 con el mismo nonce
    cipher = Salsa20.new(key=key, nonce=nonce)
    
    # Desencriptar el mensaje
    decrypted_message = cipher.decrypt(ciphertext)
    
    return decrypted_message.decode('utf-8')

# Clave de 32 bytes (puedes cambiarla, pero debe tener exactamente 32 caracteres)

key = 'clave_secreta_muy_segura_de_256_'  # Clave de 16 bytes


# Mensaje a encriptar
message = "Este es un mensaje secreto."

# Encriptar el mensaje
encrypted = encrypt_message_salsa20(key, message)
print(f"Mensaje Encriptado: {encrypted}")

# Desencriptar el mensaje
decrypted = decrypt_message_salsa20(key, encrypted)
print(f"Mensaje Desencriptado: {decrypted}")
