import random, hashlib
import sys, time, utils

from typing import Tuple, List, Dict, Union
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# import binascii
#
# keyPair = RSA.generate(3072)
#
# pubKey = keyPair.publickey()
# print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
# pubKeyPEM = pubKey.exportKey()
# print(pubKeyPEM.decode('ascii'))
#
# print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
# privKeyPEM = keyPair.exportKey()
# print(privKeyPEM.decode('ascii'))
#
# # encryption
# msg = 'A message for encryption'
# encryptor = PKCS1_OAEP.new(pubKey)
# encrypted = encryptor.encrypt(msg)
# print("Encrypted:", binascii.hexlify(encrypted))


class RSA(object):
    def __init__(self,
                 bit_size: int = 1024,
                 verbose=False,
                 encode_method: str = "oaep"
                 ) -> None:
        self.size = int(bit_size)
        assert self.size >= 512, "key size bit too small, it should be at least 256 bit and must be 2^n bit"
        self.verbose = verbose

        self.public_key = None
        self.private_key = None

        self.encoder = utils.DataEncoder()
        assert encode_method in self.encoder.code_type, "invalid encode type"
        self.encode_method = encode_method

    # def returnED(fn):
    #     fnPn = list()
    #     for i in range(2, fn / 2):
    #         if (fn % i == 0):
    #             fnPn.append(i)
    #     fnPn.append(fn / 2)
    #     for i in range(fn - 1, 1, -1):
    #         flag = True
    #         for j in range(len(fnPn)):
    #             if (i % fnPn[j] == 0):
    #                 flag = False
    #                 break
    #         if (flag):
    #             j = 1
    #             while True:
    #                 if (i * j % fn == 1):
    #                     return i, j
    #                 j += 1

    def generate_key_pairs(self) -> Tuple[int, int]:

        # randomly sample two large prime p and q
        p = utils.sample_prime_with_bit_size(self.size // 2)
        q = utils.sample_prime_with_bit_size(self.size - self.size // 2)
        n = p * q

        # compute the Euler function as m
        m = (p - 1) * (q - 1)

        # randomly pick an integer e that is relatively prime to m
        e = 65537 if 65537 < m else 11

        # compute integer d s.t. ed - 1 = km
        d, _ = utils.ext_euclid(e, m)

        # keep secret the private key and release the public key
        self.public_key = (n, e)
        self.private_key = (n, d)
        return (n, e)

    # def isPNs(x):
    #     for j in range(2, x):
    #         if (x % j == 0):
    #             return False
    #     return True
    # def Is_Huzhi(int_min, int_max):
    #     for i in range(2, int_min + 1):
    #         if int_min % i == 0 and int_max % i == 0:
    #             return False
    #     return True
    #
    #
    # def Creat_E(oula):
    #     top = oula
    #     while True:
    #         i = randint(2, top)
    #         for e in range(i, top):
    #             if Is_Huzhi(e, oula):
    #                 return e
    #         top = i
    #
    #
    # def Compute_D(oula, e):
    #     k = 1
    #     while (k * oula + 1) % e != 0:
    #         k += 1
    #     return int((k * oula + 1) / e)


    def encrypt(self, plain_text: Union[str, int]) -> List[int]:
        """
        Encrypt a piece of plain text into ciphertext.
        First, get the UTF-8 value of each character in str.
        We calculate the number of passwords for each UTF-8 value.
        In this way, the size of chunk can be regarded as one byte.
        """
        n, e = self.public_key

        if self.encode_method == "naive":
            bs = self.encoder.naive_encode(plain_text)
        if self.encode_method == "oaep":
            bs = self.encoder.oaep_encode(plain_text)

        t1 = time.time()
        cipher_text = [pow(u, e, n) for u in bs]
        t2 = time.time()

        if self.verbose:
            print("| encrypt {}bytes plain text in {:.3f}s".format(
                sys.getsizeof(plain_text), t2 - t1))
        return cipher_text

    def decrypt(self, cipher_text: List[int], decode_type: str) -> Union[str, int]:
        """
        Use pow() to quickly compute c ^ d % n.
        return bytes.
        """
        n, d = self.private_key

        t1 = time.time()
        plain_text = [pow(c, d, n) for c in cipher_text]
        t2 = time.time()

        if self.verbose:
            print("| decrypt {}bytes cipher text in {:.3f}s".format(
                sys.getsizeof(cipher_text), t2 - t1))
        if self.encode_method == "naive":
            plain_text = self.encoder.naive_decode(decode_type, plain_text)
        if self.encode_method == "oaep":
            plain_text = self.encoder.oaep_decode(decode_type, plain_text)
        return plain_text


def test_rsa(rsa_encode_method):
    """
    set different sizes
    test rsa
    """
    sizes = [512, 1024, 2048]
    for size in sizes:
        r = RSA(size, verbose=True, encode_method=rsa_encode_method)
        pk = r.generate_key_pairs()
        print("| Test RSA algorithm with key size {}bit".format(size))
        with open("test.txt", "r") as f:
            for text in f.readlines():
                text_type, text = text.strip().split('\t')
                if text_type != "str":
                    text = eval(text)
                ct = r.encrypt(text)
                pt = r.decrypt(ct, text_type)
                assert pt == text, "failed"
        print("| All test passed!")

def test_oaep_encode_and_decode():
    encoder = utils.DataEncoder()
    testsets = [
        ["str", "Network secruity is a interesting topic"],
        ["str", "CS6501 is a great class."],
        ["int", 34253623],
        ["int", 2342345844594389],
    ]
    for test_type, test_case in testsets:
        l = encoder.oaep_encode(test_case)
        ll = encoder.oaep_decode(test_type, l)
        print(test_case)
        print(ll)
        assert ll == test_case, "failed"