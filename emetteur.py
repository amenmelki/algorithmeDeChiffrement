from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_message(public_key_file, message):
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return encrypted_message

# L'émetteur chiffre un message
message = "Bonjour, ceci est un message sécurisé."
encrypted_message = encrypt_message("public.pem", message)

print("Message chiffré :", encrypted_message)
