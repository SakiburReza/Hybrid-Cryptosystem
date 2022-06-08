import socket
from turtle import pu     
from AES_RSA_1705106 import *
import pickle

s = socket.socket()        
print ("Socket successfully created")
 
port = 12345               

s.bind(('', port))        
print ("socket binded to %s" %(port))

s.listen(5)    
print ("socket is listening")           




def storeKeys(PRK):
    file1 = open("./Don't Open This/myfile.txt","r+")
    key = str(PRK[0]) +","+ str(PRK[1])+"\n"
    file1.write(key)
    file1.close()

def messageEncryption(plainText,key):
    aes = AES()
    aes.aes_constructor(key)
    key = aes.keyPadding()
  
    aes_cipher=aes.encrypt(plainText)

    print("Execution Time:")
    print("Key Scheduling: ",aes.keySchedulingTime)
    print("Encryption Time: ",aes.encryptionTime)

    rsa = RSA()
    rsa.constructor_RSA(32)
    publicKey, privateKey = rsa.keyPairGeneration()
    
    rsa_cipherText = rsa.encrypt(publicKey,key)
    storeKeys(privateKey)
    publicKeyInList = list(publicKey)
    return aes_cipher,rsa_cipherText,publicKeyInList


c, addr = s.accept()    
print ('Got connection from', addr )
while True:
 
    plainText = input("Plain Text: ")
    print("In Hex: ",textTohex(plainText))
    key = input("Key:")
    print("In Hex: ",textTohex(key))
    CT,EK,PUK = messageEncryption(plainText,key)
    c.send(CT.encode())
    encryptedKey = pickle.dumps(EK)
    #publicKey = pickle.dumps(PUK)
    c.send(encryptedKey)
    #c.send(publicKey)
    #c.send(EK)
    #c.send(PUK)
 
  # Close the connection with the client
  #c.close()
   
  # Breaking once connection closed
  #break
