from Crypto.PublicKey import RSA
from Crypto import Random
import base64
from Crypto.Hash import SHA256


random_generator = Random.new().read
key = RSA.generate(1024, random_generator)

public_key = key.publickey()

message = raw_input("Introduce the text you want to encrypt: ")

print ""

enc_data = public_key.encrypt(message, 32)
hash = SHA256.new(message).digest()
signature = key.sign(hash, '')


print "Encrypted text: " + base64.b64encode("".join(enc_data))

print "Signature: " + str(signature)

print ""

decrypted_message = key.decrypt(enc_data)
print "Decrypted text: " + decrypted_message

hash = SHA256.new(decrypted_message).digest()
print "Is the signature correct?: " + str(public_key.verify(hash, signature))


