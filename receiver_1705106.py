import pickle
import socket            
from AES_RSA_1705106 import *
s = socket.socket()        
port = 12345               
s.connect(('127.0.0.1', port))

def readPRK():
    file2 = open("./Don't Open This/myfile.txt","r+")
    prk = file2.readline().split(",")
    d = int(prk[0])
    n = int(prk[1])
    return (d,n)


def writeText(text):
    file2 = open("./Don't Open This/myfile.txt","r+")
    file2.write(text)

while True:
    cipher = (s.recv(1024).decode())
    print("Cipher Text In Hex: ",cipher)
    print("In Ascii: ",hexToText(cipher))
    EK = pickle.loads(s.recv(1024))
    
    EK = [int(i) for i in EK]
    d,n=readPRK()
    rsa = RSA()
    rsa.constructor_RSA(32)
    aes_key = rsa.decrypt((d,n),EK)
    aes = AES()
    aes.aes_constructor(aes_key)
    plainText = aes.decrypt(cipher)
    print("Plain Text In Hex: ",textTohex(plainText))
    print("Plain Text: ",plainText)
    writeText(plainText)

    print("Decryption Time: ",aes.decryptionTime)

# close the connection
#s.close()  