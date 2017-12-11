import binascii
from Crypto.Cipher import AES
import os, random, sys
from binascii import unhexlify


# Credit to Chris Coe for this code
# Requires pycrypto, which does indeed work for python3

def long_to_bytes (val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.
    :param long val: The value to pack
    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.
    If you want byte- and word-ordering to differ, you're on your own.
    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]
    return s

def encrypt(key, raw):
    '''
    Takes in a string of clear text and encrypts it.

    @param raw: a string of clear text
    @return: a string of encrypted ciphertext
    '''
    if (raw is None) or (len(raw) == 0):
        raise ValueError('input text cannot be null or empty set')
    #print (len(raw))
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

    res = long_to_bytes(len(hex))
    hex_res = binascii.hexlify(res).decode('utf-8')
    while len(hex_res) < 32:
        hex_res = '0' + hex_res
    last_block=hex_res
    hex += 'ff'
    while len(hex) % 32 != 0:
        hex += '00'
    for i in range(0, len(hex), 32):
        before_enc = xor_hex_string(last_block, hex[i:i+32])
        #print(len(before_enc))
        last_block = encrypt(key, binascii.unhexlify(before_enc))
        result += last_block
    return binascii.unhexlify(result)


def main(args):
    input = ""
    tagfile = ""
    keyfile=""

    for a in range(0,len(args)):
        if args[a] == "-k":
            keyfile = args[a+1]
        if args[a] == "-m":
            input = args[a+1]
        if args[a]=="-t":
            tagfile=args[a+1]
        if args[a]=="-f":
            function=args[a+1]

    infile=open(input,"rb")
    data= infile.read()
    hex_data = binascii.hexlify(data).decode('utf-8')
    infile.close()

    keyring=open(keyfile,"r")
    key= binascii.unhexlify(keyring.read())
    answer = cbc_encrypt(key, hex_data)[:32]

    if function == "encrypt":
        outfile = open(tagfile, "wb")
        outfile.write(answer)
        outfile.close()
    if function == "decrypt":
        tagbit = open(tagfile, "rb")
        tag = tagbit.read()
        tagbit.close()
        if(tag == answer):
            print("True")
        else:
            print("False")



if __name__ == "__main__":
    main(sys.argv[1:])