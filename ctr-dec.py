import binascii
from multiprocessing import Process
from Crypto.Cipher import AES
import os, random

def xor_hex_string(a, b):
    c, d = binascii.unhexlify(a), binascii.unhexlify(b)
    result = bxor(c, d)
    return binascii.hexlify(result).decode('utf-8')

def bxor(b1, b2): # use xor for bytes
    result = bytearray()
    for b1, b2 in zip(b1, b2):
        result.append(b1 ^ b2)
    return result

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

def get_hex_iv():
    return binascii.hexlify(os.urandom(16)).decode('utf-8')

def ctr_encrypt(key, hex, iv):
    last_block = encrypt(key, binascii.unhexlify(iv))
    result = xor_hex_string(last_block, hex)
    return result

def ctr_decrypt(key, hex, iv):
    hold = binascii.hexlify(decrypt(key, iv)).decode('utf-8')
    result = xor_hex_string(hold, hex)
    return result




if __name__ == "__main__":
    input = ""
    output = ""
    keyfile=""
    ivfile =""
    checkiv=0

    for a in range(1,len(sys.argv)):
        if sys.argv[a] == "-k":
            keyfile = sys.argv[a+1]
        if sys.argv[a] == "-v":
            ivfile = sys.argv[a+1]
            checkiv =1
        if sys.argv[a]=="-o":
            output=sys.argv[a+1]
        if sys.argv[a] == "-i":
            input = sys.argv[a + 1]

    infile=open(input,"r")
    hex_data= infile.read()
    infile.close()
    outfile=open(output,"w")
    keyring=open(keyfile,"r")
    key= keyring.read()

    if checkiv:
        ivhold=open(ivfile,"r")
        iv=ivhold.read()

    else:
        iv = binascii.hexlify(hex_data[:32]).decode('utf-8')
    #key = bytes("1234567890abcdef1234567890abcdef", encoding='utf-8')
    #hex_data = binascii.hexlify(bytes("1234567890abcdef", encoding='utf-8')).decode('utf-8')

    last_block=iv
    deanswer=""
    count=1
    print(iv)
    print(iv+1)
    pool = ThreadPool(processes = 4)

    for i in range(0, len(hex_data), 32):
        p = pool.apply_async(ctr_decrypt,(key,hex_data[i:i+32],iv+count))
        deanswer += p.get()

    outfile.write(deanswer)