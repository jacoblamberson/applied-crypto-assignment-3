import binascii
from Crypto.Cipher import AES
import os, random, sys
from binascii import unhexlify

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
    publicKey= binascii.unhexlify(public.read())
    close(public)

    private = open(privatefile, "r")
    privateKey = binascii.unhexlify(private.read())
    close(private)

    validate = open(validatefile, "r")
    validateKey = binascii.unhexlify(validate.read())
    close(validate)

    if function == "lock":
        for filename in os.listdir(directory):
            {

            }
    elif function == "unlock":
        for filename in os.listdir(directory):
            {

            }