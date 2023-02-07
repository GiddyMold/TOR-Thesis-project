import hashlib
import random
from random import randrange
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

class AESCypher(object):
    def __init__(self, key):                                            #zaaplikowanie wartości klucza do algorytmu AES
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()
    def pad(self, plain_message):                                       #wypełeninie wiadomości losowym zestawem znaków
        pad_bytes = self.block_size - len(plain_message) % self.block_size
        random_string = chr(pad_bytes)
        padding_str = pad_bytes * random_string
        pad_plain_message = plain_message + padding_str
        return pad_plain_message                                        #zwrócenie wypełnionej wiadomości
    @staticmethod
    def unpad(plain_message):                                           #usunięcie wypełnienia do wiadomości podstawowej
        last_char = plain_message[len(plain_message) - 1:]
        return plain_message[:-ord(last_char)]                          #zwrócenie oryginalnej wiadomości
    def encrypt(self, plain_message):                                   #zaszyfrowanie wiadomości algorytmem AES
        plain_message = self.pad(plain_message)
        iv = Random.new().read(self.block_size)
        cypher = AES.new(self.key, AES.MODE_CBC, iv)
        encr_message = cypher.encrypt(plain_message.encode())
        return b64encode(iv + encr_message).decode("utf-8")             #zwrócenie zaszyfrowanej wiadomości
    def decrypt(self, encr_message):                                    #odszyfrowanie wiadomości
        encr_message = b64decode(encr_message)
        iv = encr_message[:self.block_size]
        cypher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_message = cypher.decrypt(encr_message[self.block_size:]).decode("utf-8")
        return self.unpad(plain_message)                                #zwrócenie odszyfrowanej wiadomości

n = 3 # ilość węzłów
src = "1.1.1.1"
dest = "142.250.186.206 [www.google.com]" # www.google.com
plain_message = "hello"
key = []                 # node[x] - gdzie x = 0 lub 1 lub 2
node1 = []               # node[0] = adres ip
node2 = []               # node[1] = adres źródłowy
node3 = []               # node[2] = adres docelowy

for x in range(1,n+1):
    a = randrange(1,255)
    while a == 10:
        a = randrange(0,255)
    if(a == 192):
        b = randrange(0,255)
        while b == 168:
            b = randrange(0,255)
    elif(a == 172):
        b = randrange(0,255)
        while b >= 16 and b <= 31:
            b = randrange(0,255)
    else:
        b = randrange(0,255)
    c = randrange(0,255)
    d = randrange(1,254)

    ip = str(a) + "." + str(b) + "." + str(c) + "." + str(d)

    if(x == 1):
        node1.append(ip)
        node1.append(src)
    if(x == 2):
        node2.append(ip)
        node2.append(node1[0])
        node1.append(node2[0])
    if(x == 3):
        node3.append(ip)
        node3.append(node2[0])
        node2.append(node3[0])
        node3.append(dest)
    
    key.append(hex(random.getrandbits(128)))

key1 = AESCypher(str(key[0]))
key2 = AESCypher(str(key[1]))
key3 = AESCypher(str(key[2]))

message1 = key3.encrypt(plain_message)
message2 = key2.encrypt(message1)
message3 = key1.encrypt(message2)
decrypted_message3 = key1.decrypt(message3)
decrypted_message2 = key2.decrypt(message2)
decrypted_message1 = key3.decrypt(message1)

print("Topologia:")
print("Adres PC: " + src)
print("Adres węzła nr 1: " + node1[0])
print("Adres węzła nr 2: " + node2[0])
print("Adres węzła nr 3: " + node3[0])
print("Adres serwera: " + dest + "\n")

print("Parametry pakietu z punktu widzenia węzła nr 1:")
print("Adres węzła: " + node1[0])
print("Adres źródłowy: " + node1[1])
print("Adres docelowy: " + node1[2])
print("Treść zaszyfrowanej wiadomości: " + message3)
print("Treść odszyfrowanej wiadomości: " + decrypted_message3)
print("Znany klucz symetryczny (nr 1): " + str(key[0]) + "\n")

print("Parametry pakietu z punktu widzenia węzła nr 2:")
print("Adres węzła: " + node2[0])
print("Adres źródłowy: " + node2[1])
print("Adres docelowy: " + node2[2])
print("Treść zaszyfrowanej wiadomości: " + message2)
print("Treść odszyfrowanej wiadomości: " + decrypted_message2)
print("Znany klucz symetryczny (nr 2): " + str(key[1]) + "\n")

print("Parametry pakietu z punktu widzenia węzła nr 3:")
print("Adres węzła: " + node3[0])
print("Adres źródłowy: " + node3[1])
print("Adres docelowy: " + node3[2])
print("Treść zaszyfrowanej wiadomości: " + message1)
print("Treść odszyfrowanej wiadomości: " + decrypted_message1)
print("Znany klucz symetryczny (nr 3): " + str(key[2]) + "\n")

print("Parametry pakietu z punktu widzenia serwera:")
print("Adres węzła: " + dest)
print("Adres źródłowy: " + node3[0])
print("Treść odszyfrowanej wiadomości: " + plain_message + "\n")