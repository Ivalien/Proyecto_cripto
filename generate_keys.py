import rsa

# Crear llave publcia y privada
(pubkey, privkey) = rsa.newkeys(2048)

# Guardamos la llave publica y privada en archivos de texto
with open('publickey.key', 'wb') as key_file:
    key_file.write(pubkey.save_pkcs1('PEM'))
with open('privatekey.key', 'wb') as key_file:
    key_file.write(privkey.save_pkcs1('PEM'))