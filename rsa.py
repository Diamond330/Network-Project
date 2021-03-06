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
    def __init__(self, bit_size = 1024,  encode_method = "oaep"):
        self.size = int(bit_size)
        self.public_key = None
        self.private_key = None
        self.encoder = utils.DataEncoder()
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

    def generate_key_pairs(self):

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


    def encrypt(self, plain_text):
        n, e = self.public_key

        if self.encode_method == "naive":
            bs = self.encoder.naive_encode(plain_text)
        if self.encode_method == "oaep":
            bs = self.encoder.oaep_encode(plain_text)

        t1 = time.time()
        cipher_text = [pow(u, e, n) for u in bs]
        t2 = time.time()

        print("encrypt {} bytes text in {:.3f}s".format(sys.getsizeof(plain_text), t2 - t1))
        return cipher_text

    def decrypt(self, cipher_text, decode_type):
        n, d = self.private_key

        t1 = time.time()
        plain_text = [pow(c, d, n) for c in cipher_text]
        t2 = time.time()

        print("decrypt {} bytes cipher text in {:.3f}s".format(sys.getsizeof(cipher_text), t2 - t1))
        if self.encode_method == "naive":
            plain_text = self.encoder.naive_decode(decode_type, plain_text)
        if self.encode_method == "oaep":
            plain_text = self.encoder.oaep_decode(decode_type, plain_text)
        return plain_text