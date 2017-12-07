import binascii
from Crypto.Cipher import AES
import os


# Credit to Chris Coe for this code
# Requires pycrypto, which does indeed work for python3

def encrypt(key, raw):
    '''
    Takes in a string of clear text and encrypts it.

    @param raw: a string of clear text
    @return: a string of encrypted ciphertext
    '''
    if (raw is None) or (len(raw) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(raw)
    return binascii.hexlify(bytearray(ciphertext)).decode('utf-8')


def decrypt(key, enc):
    if (enc is None) or (len(enc) == 0):
        raise ValueError('input text cannot be null or empty set')
    enc = binascii.unhexlify(enc)
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    enc = cipher.decrypt(enc)
    return enc#.decode('utf-8')


def bxor(b1, b2): # use xor for bytes
    result = bytearray()
    for b1, b2 in zip(b1, b2):
        result.append(b1 ^ b2)
    return result


def get_hex_iv():
    return binascii.hexlify(os.urandom(16)).decode('utf-8')


def xor_hex_string(a, b):
    c, d = binascii.unhexlify(a), binascii.unhexlify(b)
    result = bxor(c, d)
    return binascii.hexlify(result).decode('utf-8')


# Takes a hex string and binary key
# Returns hex-represented encrypted data
def cbc_encrypt(key, hex):
    result = ""
    iv = get_hex_iv()
    result += iv

    hex += 'ff'
    while len(hex) % 32 != 0:
        hex += '00'

    last_block = iv
    for i in range(0, len(hex), 32):
        before_enc = xor_hex_string(last_block, hex[i:i+32])
        last_block = encrypt(key, binascii.unhexlify(before_enc))
        result += last_block
    return result

# Returns binary result
def cbc_decrypt(key, hex):
    result = ""
    iv = hex[:32]#binascii.hexlify(decrypt(key, hex[:32])).decode('utf-8')
    last_block = iv
    for i in range(32, len(hex), 32):
        decrypted = binascii.hexlify(decrypt(key, hex[i:i+32])).decode('utf-8')
        message = xor_hex_string(decrypted, last_block)
        last_block = hex[i:i+32]
        result += message
    result = result[:result.rfind('ff')]
    return binascii.unhexlify(result)


if __name__ == "__main__":
    key = bytes("1234567890abcdef1234567890abcdef", encoding='utf-8')
    hex_data = binascii.hexlify(bytes("1234567890abcdef1234567890abcdef1234567890abcdefpoi", encoding='utf-8')).decode('utf-8')
    ct = encrypt(key, "1234567890abcdef")
    dt = decrypt(key, ct)
    rnd = get_hex_iv()
    print(ct)
    print(dt)
    print(rnd)
    r = xor_hex_string('11', '22')
    print(r)
    print(xor_hex_string(r, '11'))
    print(xor_hex_string(r, '22'))
    print(binascii.unhexlify(hex_data))
    print(hex_data)
    encrypted = cbc_encrypt(key, hex_data)
    print(encrypted)
    decrypted = cbc_decrypt(key, encrypted)
    print(decrypted.decode('utf-8'))