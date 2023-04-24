from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter

# Function to encrypt plaintext using AES in Galois Counter Mode
def aes_gcm_encrypt(plaintext, key):
    nonce = get_random_bytes(12)                                # Generate a 12-byte random nonce
    counter = Counter.new(128, nonce)                           # Create a 128-bit counter object from the nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)            # Create a new AES-GCM cipher object with the given key, nonce, and counter
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)      # Encrypt the plaintext and get the authentication tag
    return (ciphertext, nonce, tag)

# Function to decrypt ciphertext using AES in Galois Counter Mode
def aes_gcm_decrypt(ciphertext, nonce, tag, key):
    counter = Counter.new(128, nonce)                           # Create a 128-bit counter object from the given nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)            # Create a new AES-GCM cipher object with the given key, nonce, and counter
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)      # Decrypt the ciphertext and verify the authentication tag
    return plaintext


key = get_random_bytes(16) # Generate a 16-byte random key
#plaintext = b'This is a very secret message.' # Define the plaintext to be encrypted

plaintext = input().encode()
ciphertext, nonce, tag = aes_gcm_encrypt(plaintext, key) # Encrypt the plaintext using AES-GCM with the randomly generated key
#print(nonce)
print('Plaintext:', plaintext.decode())
print('Ciphertext:', ciphertext)

decrypted_plaintext = aes_gcm_decrypt(ciphertext, nonce, tag, key) # Decrypt the ciphertext using AES-GCM with the nonce, authentication tag, and the same key
print('Plaintext:', plaintext.decode())
print('Ciphertext:', ciphertext)
print('Decrypted plaintext:', decrypted_plaintext.decode())
