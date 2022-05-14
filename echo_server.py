import os
import logging
import socket
import tqdm
from Crypto.Cipher import AES
from tkinter import *
import rsa

def get_data():
    # Se crea un socket TCP/IP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Se une el socket creado a puerto local 10000
    server_address = ('localhost', 5001)
    sock.bind(server_address)
    # Recibe 4096 bytes
    BUFFER_SIZE = 4096
    SEPARATOR = "<SEPARATOR>"
    # El servidor se mantiene a la escucha de una solicutd de conexion
    sock.listen(1)
    #Esperando la conexion mientras que no cambie el calor a 0
    print('Esperando Conexion entrante')
    connection, client_address = sock.accept()
    print('Conexion desde: ', client_address)
    # Se recibe la informacion del archivo entrante por medio del socket del cliente
    received = connection.recv(BUFFER_SIZE).decode()
    filename, filesize = received.split(SEPARATOR)
    filename = os.path.basename(filename)
    #Convierte el tamaño de archivo a entero
    filesize = int(filesize)
    #Barra de progreso que indica cuanta informacion se ha obtenido
    progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "wb") as f:
        while True:
            # Lee el valor del buffer que esta recibiendo
            bytes_read = connection.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            # Cuando termina de leer el budder escribe en un archivo los datos
            f.write(bytes_read)
            # Actualiza la barra de profreso
            progress.update(len(bytes_read))
    sock.close()

#Llave con las que se encrypto el archivo desde el usuario
key=b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")
#Se descrypta el mensaje enviado mediante texto plano
def decrypt_file_message(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    file_name="message"
    with open(file_name, 'wb') as fo:
        fo.write(dec)
#Revisa el contenido de llave privada del archivo firmado recibido desde el cliente
def decrypt_file_sign(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    file_name="Signature.txt"
    with open(file_name, 'wb') as fo:
        fo.write(dec)
#Revisamos el contenido de la firma proveniente del emisor
def file_open(file):
    key_file = open(file, 'rb')
    key_data = key_file.read()
    key_file.close()
    return key_data


def get_user_accesss():
    #Llamado a la funcion para desencriptar el mesaje
    decrypt_file_message('Test.enc', key)

def check_digital_siganture():
    # La llave publica del emisor es utilizda para descifrar el mesaje firmado
    pubkey = rsa.PublicKey.load_pkcs1(file_open('publickey.key'))
    #Se guarda el valor del mensaje puro y el de el mesaje con fimra
    #Para posteriormente compararlos, si son iguales el mensaje
    #No fue manipulado
    message = file_open('message')
    signature = file_open('Signature_file')
    # Se compara la frima del emisor con el mensaje obtenido
    try:
        rsa.verify(message,signature,pubkey)
        print("El mensaje concicide con la llave privada del emisor")

    except:
        print("El mensaje puede haber sido manipulado por un externo")

# Ventana princpial.
def ventana_inicio():
    global ventana_principal
    pestas_color = "DarkGrey"
    ventana_principal = Tk()
    ventana_principal.geometry("300x250")  # DIMENSIONES DE LA VENTANA
    ventana_principal.title("Login para Desencriptar archivo")  # TITULO DE LA VENTANA
    Label(text="Login con user", bg="Dark Gray", width="300", height="2",
          font=("Calibri", 13)).pack()  # ETIQUETA CON TEXTO
    Label(text="").pack()
    Button(text="Acceder", height="2", width="30", bg=pestas_color, command=login).pack(padx=10, pady=40)
    Label(text="").pack()
    ventana_principal.mainloop()
# Abre la venta de login .
def login():
    global ventana_login
    ventana_login = Toplevel(ventana_principal)
    ventana_login.title("Acceso a la cuenta")
    ventana_login.geometry("300x250")
    Label(ventana_login, text="Introduzca nombre de usuario y contraseña").pack()
    Label(ventana_login, text="").pack()

    global verifica_usuario
    global verifica_clave

    verifica_usuario = StringVar()
    verifica_clave = StringVar()

    global entrada_login_usuario
    global entrada_login_clave

    Label(ventana_login, text="Nombre usuario * ").pack()
    entrada_login_usuario = Entry(ventana_login, textvariable=verifica_usuario)
    entrada_login_usuario.pack()
    Label(ventana_login, text="").pack()
    Label(ventana_login, text="Contraseña * ").pack()
    entrada_login_clave = Entry(ventana_login, textvariable=verifica_clave, show='*')
    entrada_login_clave.pack()
    Label(ventana_login, text="").pack()
    Button(ventana_login, text="Acceder", width=10, height=1, command=verifica_login).pack()


# VENTANA "VERIFICACION DE LOGIN".

def verifica_login():
    usuario1 = verifica_usuario.get()
    clave1 = verifica_clave.get()
    entrada_login_usuario.delete(0, END)  # BORRA INFORMACIÓN DEL CAMPO "Nombre usuario *" AL MOSTRAR NUEVA VENTANA.
    entrada_login_clave.delete(0, END)  # BORRA INFORMACIÓN DEL CAMPO "Contraseña *" AL MOSTRAR NUEVA VENTANA.

    lista_archivos = os.listdir()  # GENERA LISTA DE ARCHIVOS UBICADOS EN EL DIRECTORIO.
    # SI EL NOMBRE SE ENCUENTRA EN LA LISTA DE ARCHIVOS..
    if usuario1 in lista_archivos:
        archivo1 = open(usuario1, "r")  # APERTURA DE ARCHIVO EN MODO LECTURA
        verifica = archivo1.read().splitlines()  # LECTURA DEL ARCHIVO QUE CONTIENE EL nombre Y contraseña.
        # SI LA CONTRASEÑA INTRODUCIDA SE ENCUENTRA EN EL ARCHIVO...
        if clave1 in verifica:
            logging.info('Usuario %s ingreso con exito',usuario1)
            exito_login()  # ...EJECUTAR FUNCIÓN "exito_login()"
        # SI LA CONTRASEÑA NO SE ENCUENTRA EN EL ARCHIVO....
        else:
            no_usuario()  # ...EJECUTAR "no_clave()"
            logging.warning('Usuario %s sin credenciales intento acceder con contraseña %s', usuario1,clave1)
    else:
        no_usuario()  # ...EJECUTAR "no_clave()"
        logging.warning('Usuario %s sin credenciales intento acceder', usuario1)


# VENTANA "Login finalizado con exito".

def exito_login():
    global ventana_exito
    ventana_exito = Toplevel(ventana_login)
    ventana_exito.title("Exito")
    ventana_exito.geometry("150x100")
    Label(ventana_exito, text="Login finalizado con exito").pack()
    Button(ventana_exito, text="OK", command=borrar_exito_login).pack()
    get_user_accesss()
# VENTANA DE "Usuario no encontrado".

def no_usuario():
    global ventana_no_usuario
    ventana_no_usuario = Toplevel(ventana_login)
    ventana_no_usuario.title("ERROR")
    ventana_no_usuario.geometry("150x100")
    Label(ventana_no_usuario, text="Usuario  o clave no encontrado").pack()
    Button(ventana_no_usuario, text="OK", command=borrar_no_usuario).pack()  # EJECUTA "borrar_no_usuario()"
    login()
# CERRADO DE VENTANAS

def borrar_exito_login():
    ventana_exito.quit()

def borrar_no_usuario():
    ventana_no_usuario.destroy()

def crear_login_file():
    fichero_log = os.path.join("/Users/ivanmendoza/PycharmProjects/encrypt_signed_file", 'Logfile.log')
    print('Archivo Log en ', fichero_log)
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s : %(levelname)s : %(message)s',
                        filename=fichero_log,
                        filemode='w', )
#Esperamos recibiri los 2 archivos necesarios
get_data()
get_data()
#Creamos el archivo de LOG para registrar los accesos
crear_login_file()
#Inicializamos la interfas grafica para solicitar user y contraseña
ventana_inicio()
#Verificamos que el mensaje no ha sido manipulado durante el envio
check_digital_siganture()