from Crypto.Cipher import AES
from Crypto import Random
import rsa
import socket
import tqdm
import os


#Funcion para encriptar el texto plano del archivo
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)
def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

#Encriptacion de todas las lineas del archivo de texto
def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".enc", 'wb') as fo:
        fo.write(enc)

#Llave  utilizada para encriptar el archivo, esta puede ser generada aleatoriamente
#Para mostrar la practica se mantiene la misma llave privada para cada envio
key = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'


#Se lee el archivo de nuestra llave
def file_open(file):
    key_file = open(file, 'rb')
    key_data = key_file.read()
    key_file.close()
    return key_data



#Llamado a la funcion de encriptar
encrypt_file('Test', key)
# Open private key file and load in key
privkey = rsa.PrivateKey.load_pkcs1(file_open('privatekey.key'))
# Se lea diciona un hash a nuestro archivo para posteriormente firmarlo
message = file_open('Test')
hash_value = rsa.compute_hash(message, 'SHA-256')
# Firma del mensaje con la llave privada del usuario
signature = rsa.sign(message, privkey, 'SHA-256')
s = open('Signature_file','wb')
s.write(signature)

# Se crea el socket TCP/IP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Espaciador para separar la trama del archivo
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096 #4KB
filename = "Test.enc"
# Obtenemos el tamaño del archivo
filesize = os.path.getsize(filename)
# Se inidica el nombre y puerto del host del servidor
server_address = ('localhost', 5001)
print('Conexion a: {} puerto: {}'.format(*server_address))
sock.connect(server_address)
# Envia el archivo mediante el socket
sock.send(f"{filename}{SEPARATOR}{filesize}".encode())
# Barra de progreso
progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
with open(filename, "rb") as f:
    while True:
        # Se lee la cantidad de bytes del archivo
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            break
         #Se verifica que la informacion haya sido enviada por el socket
        sock.sendall(bytes_read)
        # Actualiza el progreso de la barra
        progress.update(len(bytes_read))
sock.close()