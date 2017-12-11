import binascii
from Crypto.Cipher import AES
import os, random, sys
import cbcMAC,rsa, main

from binascii import unhexlify, hexlify

if __name__ == "__main__":
    directoryfile = ""
    publicfile = ""
    privatefile=""
    validatefile=""

    for a in range(1,len(sys.argv)):
        if sys.argv[a] == "-d":
            directory = sys.argv[a+1]
        if sys.argv[a] == "-p":
            publicfile = sys.argv[a+1]
        if sys.argv[a]=="-r":
            privatefile=sys.argv[a+1]
        if sys.argv[a]=="-vk":
            validatefile=sys.argv[a+1]
        if sys.argv[a]=="-f":
            function=sys.argv[a+1]

    public=open(publicfile,"r")
    publicKey= public.read()
    public.close()

    private = open(privatefile, "r")
    privateKey = private.read()
    private.close()

    validate = open(validatefile, "r")
    validateKey = validate.read()
    validate.close()


    if function == "lock":
        ranKey = open("AESkey", "wb")
        holder = binascii.hexlify(os.urandom(32))
        print(holder)
        ranKey.write(holder)
        rsa.main(['-k','AESkey','-p','pub','-o','symmetric key manifest','-i','AESkey','-f','rsa-encrypt'])
        rsa.main(['-k', 'AESkey', '-p', 'pub', '-o', 'manifest sign', '-i', 'symetric key manifest','-f','rsa-sign' ])
        for filename in os.listdir(directory):
                output=filename + "L"
                data = open(filename, "r")
                plainstuff = data.read()
                data.close()
                encryptstuff=main.cbc_encrypt(holder,plainstuff)
                finalplace = open(output, "wb")
                finalplace.write(encryptstuff)
                finalplace.close()
                tagname=filename +"T"
                cbcMAC.encrypt(['-k','AESkey','-m','output','-t','tagname','-f','encrypt'])
                os.remove(filename)
    elif function == "unlock":
        for filename in os.listdir(directory):
