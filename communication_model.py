import os, random, utils

import socket
from typing import Dict, List, Tuple
from rsa import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def WUP_request(content, mac, imei):
    requests = []
    for i in range(0, len(content), 1024):
        sub_content = content[i: min(len(content), i + 1024)]
        if len(sub_content) < 1024:
            sub_content += " " * (1024 - len(sub_content))
        text = "\t".join([sub_content, mac, imei]).encode('utf-8')
        sha = SHA256.new()
        sha.update(text)
        checksum = sha.hexdigest().encode('utf-8')
        requests.append(text + checksum)
    return requests


class Client(object):
    def __init__(self, encode_method = "oaep"):
        self.id = random.randint(0, 1 << 64)
        self.rsa = RSA(encode_method = encode_method)
        self.rsa.generate_key_pairs()
        self.mac = str(random.randint(1000000, 9999999))
        self.imei = str(random.randint(1000000, 9999999))

    def socket_connect_client(self, text):
        client = socket.socket()
        ip_port = ('192.168.1.51', 8000)
        client.connect(ip_port)

        while True:
            data = client.recv(1024)
            client.send(text)


    def send_request(self, content):

        # Generate a 128-bit AES session key
        aes_key = random.getrandbits(128)
        aes = AES.new(aes_key.to_bytes(16, 'big'))

        # Use a 1024 bits RSA public key
        encrypted_aes_key = self.rsa.encrypt(aes_key)

        # Use WUP_request to convert the content to requests
        requests = WUP_request(content, self.mac, self.imei)

        # Use AES to encrypt the request
        encrypted_requests = []
        for request in requests:
            encrypted_requests.append(aes.encrypt(request))

        # Put the encrypted aes key and requests in a list and send it to the server
        result = []
        for encrypted_request in encrypted_requests:
            result.append((self.id, encrypted_aes_key, encrypted_request))

        return result


class Server(object):
    def __init__(self):
        self.client2rsa: Dict[int, RSA] = {}

    def socket_connect_server(self, content):
        sk = socket.socket()

        ip_port = ('192.168.1.51', 8000)
        sk.bind(ip_port)

        sk.listen(5)
        while True:
            conn, address = sk.accept()
            conn.send(content)
            while True:
                client_data = conn.recv(1024)
                if client_data == 'exit':
                    break
                conn.send("ack".encode('utf-8'))
            conn.close()

    def register(self, client):
        self.client2rsa[client.id] = client.rsa

    def process_request(self, encrypted_requests):

        # Get the client id and encrypted aes key
        client_id, encrypted_aes_key, _ = encrypted_requests[0]

        # Decrypt the RSA-encrypted AES key it received from the client
        if client_id not in self.client2rsa.keys():
            print("User NOT registered!")
            return False

        # Decrypt the aes_key
        aes_key = self.client2rsa[client_id].decrypt(encrypted_aes_key, "int")

        # Select 128 bits as aes key
        aes_key = aes_key & utils.bit_mask(128)
        aes = AES.new(aes_key.to_bytes(16, 'big'))

        # Use aes to decrypt the request
        content = ""
        for _, _, encrypted_request in encrypted_requests:
            decrypted_request = aes.decrypt(encrypted_request)
            text = decrypted_request[:-64]
            checksum = decrypted_request[-64:]
            sha = SHA256.new()
            sha.update(text)

            # check checksum
            if checksum != sha.hexdigest().encode('utf-8'):
                print("Invalid WUP request")
                return False

            sub_content, mac, imei = text.decode('utf-8').split('\t')
            content += sub_content.strip()
        print("Valid WUP request")
        return True

