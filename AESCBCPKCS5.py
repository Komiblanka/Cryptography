import base64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import MD5

def pad(originalstring, blocklength):
    return originalstring + (blocklength - (len(originalstring) % blocklength)) * chr((blocklength - (len(originalstring) % blocklength)))

def unpad(blocks):
    return blocks[:-ord(blocks[len(blocks)-1:])]

def AES_encrypt(clear_string, userkey):
    key = MD5.new(userkey).hexdigest()
    IV = Random.new().read(AES.block_size) 
    blocks = pad(clear_string, AES.block_size)
    
    cipher = AES.new(key, AES.MODE_CBC, IV)
    
    return base64.b64encode(IV + cipher.encrypt(blocks))

def AES_decrypt(encrypted_string, userkey):
    key = MD5.new(userkey).hexdigest()
    encrypted_bits = base64.b64decode(encrypted_string)
    IV = encrypted_bits[:AES.block_size]
    
    cipher = AES.new(key, AES.MODE_CBC, IV)
    
    blocks = cipher.decrypt(encrypted_bits[AES.block_size:])
    message = unpad(blocks).encode('utf-8')
    
    return message
    
    

mensaje = raw_input("Introduce el mensaje a cifrar: ")

encrypted = AES_encrypt(mensaje, "secret")
print "Encrypted: " + encrypted

decrypted = AES_decrypt(encrypted, "secret")
print "Decrypted: " + decrypted
