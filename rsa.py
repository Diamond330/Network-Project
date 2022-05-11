import random, hashlib
import sys, time, utils


class RSA(object):
    def __init__(self, bit_size = 1024,  encode_method = "oaep"):
        self.size = int(bit_size)
        self.public_key = None
        self.private_key = None
        self.encoder = utils.DataEncoder()
        self.encode_method = encode_method

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

