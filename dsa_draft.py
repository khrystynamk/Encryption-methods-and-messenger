"""
Module for Digital Signature Algorithm (DSA)
"""

import random
from Crypto.Util import number
from Crypto.Hash import SHA256
from math import gcd

class DSA:

    low_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                31, 37, 41, 43, 47, 53, 59, 61, 67,
                71, 73, 79, 83, 89, 97, 101, 103,
                107, 109, 113, 127, 131, 137, 139,
                149, 151, 157, 163, 167, 173, 179,
                181, 191, 193, 197, 199, 211, 223,
                227, 229, 233, 239, 241, 251, 257,
                263, 269, 271, 277, 281, 283, 293,
                307, 311, 313, 317, 331, 337, 347,
                349, 353, 359, 367, 373, 379, 383,
                389, 397, 401, 409, 419, 421, 431,
                433, 439, 443, 449, 457, 461, 463,
                467, 479, 487, 491, 499]
    
    def __init__(self) -> None:
        self._p = None
        self._q = None
        self._g = None
        self._signing_key = None # private key
        self.verification_key = None # public key

    # Below is the code 'made from scratch' that can be used instead of number.isPrime()

    # ----------------------------------------------------------------------------------

    # Step 1: Primality Testing with the Rabin-Miller Algorithm

    # def miller_rabin(self, num):
    #     """
    #     Primality Testing with the Rabin-Miller Algorithm
    #     """
    #     odd = num - 1
    #     divisions = 0
    #     # Find odd such that n-1 = 2^k * u 
    #     while (odd % 2 == 0):
    #         odd //= 2
    #         divisions += 1
    
    #     for _ in range(20):
    #         random_var = random.randrange(1, num - 1)
    #         if pow(random_var, odd, num) == 1:
    #             return True
    #         for i in range(divisions):
    #             if pow(random_var, 2**i * odd, num) == num - 1:
    #                 return True
    #     return False


    # def is_prime(self, num):
    #     """
    #     Check if the given number is a prime number.
    #     """
    #     if num < 2:
    #         return False  # 0, 1, and negative numbers are not prime
    #     if num in self.low_primes:
    #         return True

    #     # See if any of the low prime numbers can divide num
    #     for prime in self.low_primes:
    #         if num % prime == 0:
    #             return False

    #     # If all else fails, call rabinMiller() to determine if num is a prime
    #     return self.miller_rabin(num)


    # def select_prime_divisor(self, bits_num=1024):
    #     """
    #     Return a random prime number of keysize bits in size.
    #     """
    #     while True:
    #         num = random.randrange(2 ** (bits_num - 1), 2 ** (bits_num))
    #         if self.is_prime(num):
    #             return num

    # ----------------------------------------------------------------------------------

    def exp_square(self, base, exp, mod):
        """
        Square and multiply algorithm for modular exponentiation.
        
        Parameters
        ----------
        base : int
            integer
        exp : int
            integer
        mod : int
            integer

        Returns
        -------
        int
            Y = baseˆexp mod (mod)
        """
        result = 1
        binary_exp = "{0:b}".format(exp)[::-1] #reversing the binary string
        for i in range(len(binary_exp) - 1, -1, -1):
            result = pow(result, 2)
            result = result % mod
            if binary_exp[i] == '1':
                result = (result * base) % mod
        return result

    def extended_eucledian(self, a_val, b_val):
        """
        Extended Euclidean algorithm.

        Parameters
        ----------
        a_val : int
            integer
        b_val : int
            integer
        
        Returns
        -------
        tuple
            gcd, coefficient s and coefficient t
            s and t are from formula: 1 = s * a_val + t * b_val
        """
        if b_val == 0:
            gcd, s_a, t_b = a_val, 1, 0
            return (gcd, s_a, t_b)

        s_a2, t_b2, s_a1, t_b1 = 1, 0, 0, 1
        while b_val > 0:
            q_val = a_val // b_val
            r_val = a_val - b_val * q_val
            s_a = s_a2 - q_val * s_a1
            t_b = t_b2 - q_val * t_b1
            a_val, b_val, s_a2, t_b2, s_a1, t_b1 = b_val, r_val, s_a1, t_b1, s_a, t_b

        gcd, s_a, t_b = a_val, s_a2, t_b2
        # 1 = s * a + t * b
        return (gcd, s_a, t_b)

    # Step 1: Generate public and private keys.

    def generate_keys(self):
        """
        Generating public and private keys according to the rules.
        """
        k = random.randrange(2 ** (415), 2 ** (416))
        q = number.getPrime(160)
        p = (k * q) + 1
        L = p.bit_length()
        t = random.randint(1, p - 1)
        g = self.exp_square(t, (p-1) // q, p)

        if (L >= 512 and L <= 1024 and L % 64 == 0 and (gcd(p - 1, q)) > 1 and self.exp_square(g, q, p) == 1):
            signing_key = random.randint(2, q - 1) # private_key
            verification_key = self.exp_square(g, signing_key, p) # public_key
            self._signing_key = signing_key
            self.verification_key = verification_key
            self._p = p
            self._q = q
            self._g = g
            # verification_key = [p, q, g, self.exp_square(g, signing_key, p)]
            # self.write_keys(signing_key, verification_key)
        else:
            self.generate_keys()

    # Step 2: Create signature for the user with private and public keys.

    def sign(self, message):
        """
        Create signature for the user with private and public keys.

        Parameters
        ----------
        message : str
            string

        Returns
        -------
        tuple
            signature as a pair of c_1 and c_2
        """
        while True:
            random_elem = random.randint(1, self._p - 1)
            c_1 = self.exp_square(self._g, random_elem, self._p) % self._q
            gcd = self.extended_eucledian(random_elem, self._q)[1]
            c_2 = (int("0x" + SHA256.new(message.encode('ascii')).hexdigest(), 0) + self._signing_key * c_1) * gcd % self._q
            if c_1 != 0 and c_2 != 0:
                break
        return str(c_1), str(c_2)

    # Step 3: Verify the signature to find out whether it is valid or not.

    def verify(self, message, encoded_tuple):
        """
        Verify the signature to find out whether it is valid or not.

        Parameters
        ----------
        message : str
            string
        encoded_tuple : tuple
            tuple(string)

        Returns
        -------
        string
            'Signature is valid.' -- if signature is valid
            'Invalid signature!' -- when an invalid signature is encountered
        """
        c_1, c_2 = encoded_tuple
        gcd = self.extended_eucledian(int(c_2), self._q)[1]
        t_1 = (int("0x" + SHA256.new(message.encode('ascii')).hexdigest(), 0)) * gcd % self._q
        t_2 = (gcd * int(c_1)) % self._q

        valid1 = self.exp_square(self._g, t_1, self._p)
        valid2 = self.exp_square(self.verification_key, t_2, self._p)
        valid = ((valid1 * valid2) % self._p) % self._q
        if valid == int(c_1):
            return 'Signature is valid.'
        return 'Invalid signature!'

# dsa = DSA()
# message = "Wow, hello world!"
# dsa.generate_keys()
# signed = dsa.sign(message)
# print(signed)
# verification = dsa.verify(message, signed)
# print(verification)
