# Just a heads up: the code in this file is awful
#
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
        manifest_file = directory + '/symmetric_key_manifest'
        manifest_file_signature = directory + '/symmetric_key_manifest-casig'

        if not rsa.main(['-f', 'rsa-validate', '-k', validatefile, '-m', publicfile, '-s', publicfile + '-casig']):
            exit()
        print("Validated " + publicfile)

        aeskeybytes = os.urandom(32)
        aeskeynum = int.from_bytes(aeskeybytes, 'big')
        holder = binascii.hexlify(aeskeybytes).decode('utf-8')

        aeskeyfilersa = open("AES_key_for_rsa_encryption", "w")
        aeskeyfilersa.write(str(aeskeynum))
        aeskeyfilersa.close()
        #print("AES key for rsa encryption (int): " + str(aeskeynum))
        #print(holder)
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
                encryptedstuff = unhexlify(main.cbc_encrypt(aeskeybytes,binascii.hexlify(plainstuff).decode('utf-8')))
                finalplace = open(output, "wb")
                finalplace.write(encryptedstuff)
                finalplace.close()
                tagname = actualname + "-tag"
                cbcMAC.main(['-k', 'AESkey', '-m', output, '-t', tagname, '-f', 'encrypt'])
                os.remove(actualname)
        os.remove('AESkey')
        os.rename('symmetric_key_manifest', manifest_file)
        os.rename('symmetric_key_manifest-casig', manifest_file + '-casig')
    elif function == "unlock":
        manifest_file = directory + '/symmetric_key_manifest'
        manifest_file_decrypted = directory + '/symmetric_key_manifest_decrypted'
        manifest_file_signature = directory + '/symmetric_key_manifest-casig'
        aes_key_file = 'AESkey'

        if not rsa.main(['-f', 'rsa-validate', '-k', validatefile, '-m', publicfile, '-s', publicfile + '-casig']):
            exit()
        print("Validated " + publicfile)

        if not rsa.main(['-k', publicfile, '-m', manifest_file, '-s', manifest_file_signature, '-f', 'rsa-validate']):
            exit()
        print("Validated " + manifest_file)

        rsa.main(['-k', privatefile, '-o', manifest_file_decrypted, '-i', manifest_file, '-f', 'decrypt'])
        aeskeyfile = open(manifest_file_decrypted)
        aeskeyint = int(aeskeyfile.readlines()[0])
        aeskeyfile.close()
        #print(aeskeyint)
        aeskeyhex = format(aeskeyint, 'x')
        while len(aeskeyhex) < 64:
            aeskeyhex = '0' + aeskeyhex
        #print(aeskeyhex)
        aeskeybytes = binascii.unhexlify(aeskeyhex)

        aeskeyfile = open(aes_key_file, 'w')
        aeskeyfile.write(aeskeyhex)
        aeskeyfile.close()

        for filename in os.listdir(directory):
            actualname = directory + "/" + filename
            if '-locked' in filename:
                newname = actualname.replace('-locked', '')
                tagname = newname + '-tag'
                tmptagname = newname + '-tmptag'
                tag_contents_file = open(tagname, 'rb')
                tag_contents = tag_contents_file.read()
                tag_contents_file.close()
                cbcMAC.main(['-k', aes_key_file, '-m', actualname, '-t', tmptagname, '-f', 'encrypt'])
                tmp_tag_contents_file = open(tmptagname, 'rb')
                tmp_tag_contents = tmp_tag_contents_file.read()
                tmp_tag_contents_file.close()
                #print("MAC for " + filename + ": " + str(tag_contents == tmp_tag_contents))
                if tag_contents != tmp_tag_contents:
                    print("False")
                    exit()
                print("Validated " + newname)
                #print(tag_contents)
                #print(tmp_tag_contents)
        for filename in os.listdir(directory):
            actualname = directory + "/" + filename
            if '-locked' in filename:
                newname = actualname.replace('-locked', '')
                tagname = newname + '-tag'
                tmptagname = newname + '-tmptag'
                os.remove(tagname)
                os.remove(tmptagname)
                encrypted_contents_file = open(actualname, 'rb')
                encrypted_contents = binascii.hexlify(encrypted_contents_file.read()).decode('utf-8')
                encrypted_contents_file.close()
                decrypted_contents = main.cbc_decrypt(aeskeybytes, encrypted_contents)
                decrypted_file = open(newname, 'wb')
                decrypted_file.write(decrypted_contents)
                decrypted_file.close()
                os.remove(actualname)
        os.remove(manifest_file)
        os.remove(manifest_file_decrypted)
        os.remove(aes_key_file)
        os.remove(manifest_file + '-casig')
