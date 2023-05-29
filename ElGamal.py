import random
from liststack import *

class ELGamal:

    #p_value = random.getrandbits(8192)
    p_value = random.getrandbits(1024)
    g = 2

    def __init__(self, name:str) -> None:
        """
        Initialization person after registration
        """
        self.name = name
        self.private_key = ELGamal.generate_key()
        self.public_key = self.power(ELGamal.g, self.private_key, ELGamal.p_value)

    @staticmethod
    def generate_key():
        """
        :generation key for person
        """
        secret = random.randint(pow(10, 20), ELGamal.p_value - 2)
        while not ELGamal.gcd(secret, ELGamal.p_value):
            secret = random.randint(pow(10, 20), ELGamal.p_value - 2)
        return secret

    @staticmethod
    def gcd(A:int, B:int) -> bool:
        """
        :evclid`s algorytm
        """
        balance = Stack()
        divider = B
        shared = A
        while divider % shared != 0:
            balance.push(divider % shared)
            shared = divider % shared
            divider = A

        return True if not balance.is_empty() and balance.peek() == 1 else False

    def power(self, g:int, key:int, prime:int):
        """
        :finding power between two number
        """
        res = 1
        g = g % prime

        while key > 0:
            if key % 2 == 1:
                res = (res * g) % prime
            key = key // 2
            g = (g * g) % prime

        return res

    def encryption(self, public_key:int, msg:str) -> str:
        """
        :encryption for messege
        """
        key = ELGamal.generate_key() # random integer
        g_aa = self.power(public_key, key, ELGamal.p_value)
        open_key = self.power(ELGamal.g, key, ELGamal.p_value)
        text_key = [ord(msg[i])* g_aa for i in range(len(msg))]

        return text_key, open_key


    def decryption(self, open_key:int, text_key:str) -> str:
        """
        :decryption for messege
        """
        back_key = self.power(open_key, self.private_key, ELGamal.p_value)
        string = ''
        for item in text_key:
            string += chr(int(item // back_key))
        return string




# Alica = ELGamal("Alice")
# Bob = ELGamal("BOb")
# # print(ELGamal.p_value)
# print(Bob.public_key)
# print(Alica.public_key)
# a = Alica.encryption(Bob.public_key, "Hellojg kug;iug; hgilyfuto yfuylut")
# print(Bob.decryption(a[1], a[0]))

# # print(random.randint(pow(10, 20), pow(10, 50)))
