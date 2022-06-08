from math import gcd
from bitvectordemo_1705106 import *
from BitVector import *
from collections import deque
import copy
import numpy as np
from largePrime_1705106 import *
import time

def transposeMatrix(matrix):
    for i in range(len(matrix)):
        for j in range(i+1,len(matrix[i])):
            temp = matrix[i][j]
            matrix[i][j]=matrix[j][i]
            matrix[j][i]=temp
    return matrix
def hexToMatrix(hexVal):
    matrix = []
    for i in range(4):
        temp = []
        for j in range(4):
            temp.append(BitVector(hexstring=hexVal[(i*8+j*2):(i*8+j*2+2)]))
        matrix.append(temp)
    return matrix   
def matrixToHex(matrix):
    text = ""
    for i in matrix:
      for j in i:
        text += str.upper(j.get_bitvector_in_hex())
    return text
def do_XOR_Array(array1,array2):
    temp = []
    for i in range(len(array1)):
        temp.append(array1[i] ^ array2[i])
    return temp
def textTohex(text):
    x=BitVector(textstring=text)
    hexVal=str.upper(x.get_bitvector_in_hex())
    return hexVal
def hexToText(hex):
    x = BitVector(hexstring=hex)
    text = x.get_bitvector_in_ascii()
    return text

def circularByteLeftShift(array=[],b=0):
    temp = deque(array)
    temp.rotate(b)
    array.clear()
    array.extend(list(temp))

def byteSubstitution(array):
  for i in range(len(array)):
      array[i] = BitVector(intVal=Sbox[array[i].intValue()], size=8)

def printBitVectorMatrix(matrix):
    for i in matrix:
        for j in i:
            print(j.get_bitvector_in_hex()," ",end="")
        print()
    print()
def printBitVectorArray(array):
    for i in array:
        print(i.get_bitvector_in_hex()," ",end="")
    print()


def subBytes(stateMatrix):
    for i in range(4):
      for j in range(4):
        stateMatrix[i][j] = BitVector(intVal=Sbox[stateMatrix[i][j].intValue()], size=8)
    return stateMatrix

def invSubBytes(stateMatrix):
    for i in range(4):
      for j in range(4):
        stateMatrix[i][j] = BitVector(intVal=InvSbox[stateMatrix[i][j].intValue()], size=8)
    return stateMatrix

def shiftRow(stateMatrix):
    for i in range(4):
      circularByteLeftShift(stateMatrix[i], -i)
    return stateMatrix
      
def invShiftRow(stateMatrix):
    for i in range(4):
      circularByteLeftShift(stateMatrix[i], i)
    return stateMatrix


class AES:
    key=""
    
    stateMatrix=[]
    w=[]
    keySchedulingTime=0
    encryptionTime = 0
    decryptionTime = 0
    def aes_constructor(self,key):
        self.key = key
    
    def keyPadding(self):
        if len(self.key) < 16:
            while len(self.key) != 16:
                self.key +="#"
        else :
            self.key = self.key[0:16]
        return self.key
    def g(self, row=[],rc=0):
        copyrow = copy.deepcopy(row);
        circularByteLeftShift(copyrow,-1)
        byteSubstitution(copyrow)

        round_constant = [
        BitVector(intVal=RoundConstant[rc]),
        BitVector(intVal=0, size=8),
        BitVector(intVal=0, size=8),
        BitVector(intVal=0, size=8)
        ]

        copyrow= do_XOR_Array(copyrow,round_constant)
        return copyrow

    def generateKey(self,n):
        keys = self.w[n*4:n*4+4]
        transposeMatrix(keys)
        return keys
    
    def keyScheduling(self):
        hexKey = textTohex(self.key)
        self.w = hexToMatrix(hexKey)
        rc=0
       
        for i in range(4,4*TOTAL_ROUND+4):
            temp = []
            if(i%4!=0):
                temp = do_XOR_Array(self.w[i-1],self.w[i-4])
            else:
                temp = do_XOR_Array(self.g(self.w[i-1],rc),self.w[i-4])
                rc = rc +1
            self.w.append(temp)
        
    def addRoundKey(self, rc):
        key_mat = self.generateKey(rc)
        for i in range(4):
            self.stateMatrix[i]=do_XOR_Array(self.stateMatrix[i],key_mat[i])
    def mixColumn(self):
        temp = copy.deepcopy(self.stateMatrix)
        for i in range(4):
            for j in range(4):
                sum = BitVector(intVal=0,size=8)
                for k in range(4):
                    sum = sum ^ (Mixer[i][k].gf_multiply_modular(temp[k][j],AES_modulus,8))
                self.stateMatrix[i][j]=sum
    
    def invMixColumn(self):
        temp = copy.deepcopy(self.stateMatrix)
        for i in range(4):
            for j in range(4):
                sum = BitVector(intVal=0,size=8)
                for k in range(4):
                    sum = sum ^ (InvMixer[i][k].gf_multiply_modular(temp[k][j],AES_modulus,8))
                self.stateMatrix[i][j]=sum

    def doEncryption(self, plain_text):
        hexText = textTohex(plain_text)
        self.stateMatrix = hexToMatrix(hexText)   
        self.stateMatrix = transposeMatrix(self.stateMatrix)  
        
        keySchedulingStart = time.time()
        self.keyScheduling()
        keySchedulingFinish = time.time()
        self.keySchedulingTime = keySchedulingFinish - keySchedulingStart

        encryptionStart = time.time()
        self.addRoundKey(0)
        for i in range(1,TOTAL_ROUND+1):
            self.stateMatrix=subBytes(self.stateMatrix)
            self.stateMatrix=shiftRow(self.stateMatrix)
            if(i != TOTAL_ROUND):
                self.mixColumn()
            self.addRoundKey(i)
        
        self.stateMatrix=transposeMatrix(self.stateMatrix)
        cipher_text= matrixToHex(self.stateMatrix)
        encryptionFinish = time.time()
        self.encryptionTime = encryptionFinish - encryptionStart

        return cipher_text
    def doDecryption(self,cipher_text):
        self.stateMatrix = hexToMatrix(cipher_text)
        self.stateMatrix = transposeMatrix(self.stateMatrix)
        self.keyScheduling()
        self.addRoundKey(TOTAL_ROUND)
        
        for i in reversed(range(0,TOTAL_ROUND)):
            self.stateMatrix = invShiftRow(self.stateMatrix)
            self.stateMatrix = invSubBytes(self.stateMatrix)
            self.addRoundKey(i)
            if i!=0:
                self.invMixColumn() 
        self.stateMatrix = transposeMatrix(self.stateMatrix)
        plainTextinHex = matrixToHex(self.stateMatrix)
        bitV = BitVector(hexstring=plainTextinHex)
        return bitV.get_bitvector_in_ascii()
    def encrypt(self,text):
        while len(text)%16 != 0:
            text += " "
        n = len(text)/16
        cipher=""
        for i in range(int(n)):
            temp = self.doEncryption(text[i*16:16+i*16])
            cipher+=temp
        return cipher
    def decrypt(self, cipher):
        decryptionStart = time.time()
        n = len(cipher)/32
        text=""
        for i in range(int(n)):
            temp = self.doDecryption(cipher[i*32:32+i*32])
            text += temp
        decryptionFinish = time.time()
        self.decryptionTime = decryptionFinish - decryptionStart
        return text
    

TEST = False
if TEST == True:    

    plainText = "Yes, we can do our fest hopefully"
    aes=AES()
    aesKey = "BUET CSE17 Batch"   #input("Enter encryption key: ")
    aes.aes_constructor(aesKey)
    aes.keyPadding()
    cipherText= aes.encrypt(plainText)
    ascii = aes.decrypt(cipherText)
    print("Plain Text: ", ascii)

def multiplicative_inverse(e, phi):
    x = 1
    y = 0
    x1 = 0
    y1 = 1
    a1 = e
    b1 = phi
    
    while b1 != 0:
        q = a1//b1
        x,x1 = x1, x - q * x1
        y , y1 = y1 , y-q*y1
        a1, b1 = b1 , a1-q * b1
    
    if x<0:
        return x+phi
    else:
        return x
    

def binPoww(a,b,m):
    a %= m
    res = 1
    
    while b > 0:
        if b & 1 :
            res = res * a % m
        a = a* a %m
        b >>= 1
    return res

class RSA:
    K = 16
    def constructor_RSA(self,k):
        self.K = k/2
    def keyPairGeneration(self):
        p = getPrime(int(self.K))
        q = getPrime(int(self.K))
        while p==q:
            q = getPrime(int(self.K))
        n = p * q
        phi_n = (p-1) * (q-1)
        e = random.randrange(1,phi_n)
        g = gcd(e,phi_n)

        while g!=1:
            e = random.randrange(1,phi_n)
            g = gcd(e,phi_n)

        d = multiplicative_inverse(e,phi_n)
        return ((e,n),(d,n))

    def encrypt(self,publicKey,plainText):
        e,n = publicKey
        cipherText = [binPoww(ord(char),e,n) for char in plainText]
        return cipherText
        #s = [str(i) for i in cipherText]
        #return ''.join(s)
    def decrypt(self,privateKey, cipherText):
        d,n = privateKey
        plainText = [chr(binPoww(num,d,n)) for num in cipherText]
        return ''.join(plainText)



TEST = False
if TEST==True:

    plainText = "Yes, we can do our Fest hopefully"
    rsa = RSA()
    print("K".ljust(25),"      KeyGeneration".ljust(35),"  Encryption".ljust(35),"Decryption".ljust(35))
    for i in range(4):
        k=2**(i+4)
        rsa.constructor_RSA(k)
        kst = time.time()
        publicKey, privateKey = rsa.keyPairGeneration()
        kft = time.time()
        est = time.time()
        rsa_cipherText = rsa.encrypt(publicKey,plainText)
        eft = time.time()
        dst = time.time()
        rsa_plainText = rsa.decrypt(privateKey,rsa_cipherText)
        dft = time.time()
        print(str(k).ljust(25),"     ",str(kft-kst).ljust(25),"     ",str(eft-est).ljust(25),"     ",str(dft-dst).ljust(25))
        


    print("Plain Text: ",rsa_plainText)














