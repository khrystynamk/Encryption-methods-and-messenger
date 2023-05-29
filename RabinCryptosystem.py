import random
from sympy import isprime
class RabinCryptosystem:

    def __init__(self) -> None:
        self.N = None
        self._p = None
        self._q = None

    def generate_key(self, bit_length):
        p = self.blum_prime(bit_length // 2)
        self._p = p
        q = self.blum_prime(bit_length // 2)
        self._q = q
        N = p * q

        self.N = N

    def blum_prime(self, bit_length):
        while True:
            p = random.randint(2**(bit_length-1), 2**bit_length)
            if p % 4 == 3 and RabinCryptosystem.is_prime(p) and (p != self._p):
                return p

    @staticmethod
    def is_prime(n):
        if isprime(n):
            return True

    def encrypt(self, char):
        ascii_value = ord(char)
        binary_value = bin(ascii_value)[2:]
        extended_binary = binary_value + binary_value
        # formula C = m^2 mod(n)
        c =  (int(extended_binary,2) ** 2) % self.N
        return c

    def extended_gcd(self, a, b):
        if b == 0:
            return a, 1, 0
        else:
            gcd, x, y = self.extended_gcd(b, a % b)
            return gcd, y, x - (a // b) * y

    def decrypt(self, c):
        #mp = C(p+1)/4 mod p
        #mq = C(q+1)/4 mod q
        mp = pow(c, (self._p + 1) // 4, self._p)
        mq = pow(c, (self._q + 1) // 4, self._q)

        gcd, yp, yq = self.extended_gcd(self._p, self._q)

        r1 = (yp * self._p * mq + yq * self._q * mp ) % self.N
        r2 = self.N - r1
        r3 = (yp * self._p * mq - yq * self._q * mp) % self.N
        r4 = self.N - r3


        binary_roots = [bin(i)[2:] for i in [r1, r2, r3, r4]]

        for binary in binary_roots:
            half_length = len(binary) // 2
            left_half = binary[:half_length]
            right_half = binary[half_length:]

            if left_half == right_half:
                decimal = int(left_half, 2)
                return chr(decimal)

    def encrypt_message(self, message):
        return [self.encrypt(element) for element in message]

    def decrypt_message(self, code):
        return ''.join(self.decrypt(num) for num in code)

# obj = RabinCryptosystem()
# obj.generate_key()

# message =  open('file30.txt', 'r',  encoding='UTF-8')
# message = message.read()
# print(type(message))
# print(message)
# message = 'The Rabin trapdoor'
# c = obj.encrypt_message(message)
# print(c)

# print(obj.decrypt_message(c))