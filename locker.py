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
        # FIXME - Must return true to continue
        rsa.main(['-f', 'rsa-validate', '-k', validatefile, '-m', publicfile, '-s', publicfile + '-casig'])

        aeskeybytes = os.urandom(32)
        aeskeynum = int.from_bytes(aeskeybytes, 'big')
        holder = binascii.hexlify(aeskeybytes).decode('utf-8')

        aeskeyfilersa = open("AES_key_for_rsa_encryption", "w")
        aeskeyfilersa.write(str(aeskeynum))
        aeskeyfilersa.close()
        print("AES key for rsa encryption (int): " + str(aeskeynum))
        print(holder)
        ranKey = open("AESkey", "w")
        ranKey.write(holder)
        ranKey.close()
        rsa.main(['-k', publicfile,'-o','symmetric_key_manifest','-i','AES_key_for_rsa_encryption','-f','encrypt'])
        os.remove('AES_key_for_rsa_encryption')
        rsa.main(['-k', privatefile, '-m', 'symmetric_key_manifest', '-s', 'symmetric_key_manifest-casig','-f','rsa-sign'])
        for filename in os.listdir(directory):
                actualname = directory + "/" + filename
                output = actualname + "-locked"
                data = open(actualname, "rb")
                plainstuff = data.read()
                data.close()
                encryptedstuff = main.cbc_encrypt(aeskeybytes,binascii.hexlify(plainstuff).decode('utf-8'))
                finalplace = open(output, "w")
                finalplace.write(encryptedstuff)
                finalplace.close()
                tagname = actualname + "-tag"
                cbcMAC.main(['-k', 'AESkey', '-m', output, '-t', tagname, '-f', 'encrypt'])
                os.remove(actualname)
        os.remove('AESkey')
    elif function == "unlock":
        # FIXME - Must return true to continue
        rsa.main(['-f', 'rsa-validate', '-k', validatefile, '-m', publicfile, '-s', publicfile + '-casig'])

        # FIXME - Must return true to continue
        rsa.main(['-f', 'rsa-validate', '-k', publicfile, '-m', 'symmetric_key_manifest', '-s', 'symmetric_key_manifest-casig'])


        for filename in os.listdir(directory):
            if '-locked' in filename:
                actualname = directory + "/" + filename
            elif '-tag' in filename:
                actualname = directory + "/" + filename
            else:
                print("PANIC PANIC PANIC PANIC")
