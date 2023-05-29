"""
RSA algorithm is an asymmetric cryptography algorithm. Asymmetric actually means
that it works on two different keys (public key and private key).
Public key is given to everyone to encrypt and send messages to a specific user.
The private key is kept private and used to decrypt the message.
"""
from Crypto.Util import number


class RSA:
    """
    RSA algorithm.
    """
    def __init__(self, exponent: int = 65537) -> None:
        self.__n = None
        self.__d = None
        self.exp = exponent

    @property
    def encrypt_int(self):
        """Get n."""
        return self.__n

    @property
    def decrypt_int(self):
        """Get d."""
        return self.__d

    def _valid_exponent(self, value: int):
        """
        Validate exponent.

        Parameters
        ----------
        value : int
            integer
        
        Returns
        int
            value if its type is int
        """
        if not isinstance(value, int):
            raise TypeError('invalid type, int expected')
        return value

    @staticmethod
    def extended_euclidean(a_val: int, b_val: int):
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

    def calculate_keys(self):
        """
        Generating public and private keys.
        """
        _p = number.getPrime(512)
        _q = number.getPrime(512)
        self.__n = _p * _q
        phi_n = (_p - 1) * (_q - 1)

        # enough large Fermat prime number
        _d = self.extended_euclidean(self.exp, phi_n)[1]

        # get a positive integer
        while _d + phi_n < phi_n:
            _d += phi_n

        self.__d = _d

    def encrypt(self, message: str, public_key: tuple[int]):
        """
        Ecrypting message.

        Parameters
        ----------
        message : str
            message
        public_key : tuple(int, int)
            tuple with two values: n (modulus) and e (exponent)
        
        Returns
        -------
        str
            encrypted message
        """
        n_val, e_val = public_key
        block_size = len(str(n_val)) // 3 - 1
        ascii_str = [('00' + str(ord(char)))[-3:] for char in message]
        ascii_list = []
        for j in range(0, len(ascii_str), block_size):
            ascii_list.append(''.join(ascii_str[j : j + block_size]))
        ascii_list[-1] = ascii_list[-1] + '0' * (block_size * 3 - len(ascii_list[-1]))
        encrypted_message = [str(pow(int(c), e_val, n_val)) for c in ascii_list]
        return ' '.join(encrypted_message)

    def decrypt(self, encrypted_message: str, private_key: tuple[int]):
        """
        Derypting encrypted message.

        Parameters
        ----------
        encrypted_message : str
            encrypted message
        private_key : tuple(int, int)
            tuple with two values: n (modulus) and d (private key)
        
        Returns
        -------
        str
            decrypted message
        """
        n_val, __d = private_key
        block_size = len(str(n_val)) // 3 - 1
        decrypted_message = [str(pow(int(c), __d, n_val)) for c in encrypted_message.split(' ')]
        result = ""
        for code in decrypted_message:
            code = '0' * (block_size * 3 - len(code)) + code
            for i in range(0, len(code), 3):
                if code[i : i + 3] != '000':
                    result += chr(int(code[i : i + 3]))
        return result


if __name__ == '__main__':
    r_s_a = RSA()
    r_s_a.calculate_keys()
    MES = 'Hello World! (^-^)'
    E_MES = r_s_a.encrypt(MES, (r_s_a.encrypt_int, r_s_a.exp))
    D_MES = r_s_a.decrypt(E_MES, (r_s_a.encrypt_int, r_s_a.decrypt_int))
    assert MES == D_MES
