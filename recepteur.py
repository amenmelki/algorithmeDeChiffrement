from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_message(private_key_file, encrypted_message):
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode('utf-8')

# Le récepteur déchiffre le message
decrypted_message = decrypt_message("private.pem", encrypted_message)

print("Message déchiffré :", decrypted_message)
