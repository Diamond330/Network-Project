import os, random, utils

from typing import Dict, List, Tuple
from rsa import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


"""
In the WUP request, we limit the length of the content to 1024 bytes
Content longer than limitation will be cut to pieces.
We add SHA and add the checksum at the end of each request
We use checksum to valid request, to make sure no request is missing
"""
def WUP_request(content: str, mac: str, imei: str) -> List[bytes]:
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
    # Set default rsa encode method to oaep
    # If we want to test the original ras, the encode method should be naive
    def __init__(self, rsa_encode_method: str = "oaep"):
        self.id = random.randint(0, 1 << 64)
        self.rsa = RSA(encode_method = rsa_encode_method)
        self.rsa.generate_key_pairs()
        self.mac = str(random.randint(1000000, 9999999))
        self.imei = str(random.randint(1000000, 9999999))

    """
    Encrypt the content, and return the encrypted request
    """
    def send_request(self, content) -> List[Tuple]:

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
        # Use list to store rsa when registering client
        self.client2rsa: Dict[int, RSA] = {}

    # Register the use with client_id, and save the rsa
    def register(self, client: Client) -> None:
        self.client2rsa[client.id] = client.rsa

    """
    Decrypt the encrypted requests received from client
    """
    def process_request(self, encrypted_requests: List[Tuple]) -> bool:

        # Get the client id and encrypted aes key
        client_id, encrypted_aes_key, _ = encrypted_requests[0]

        # Decrypt the RSA-encrypted AES key it received from the client
        if client_id not in self.client2rsa.keys():
            print("User is not registered!")
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
            # Get the text and checksum respectively
            text = decrypted_request[:-64]
            checksum = decrypted_request[-64:]
            sha = SHA256.new()
            sha.update(text)

            # If checksum is not equal, print the request is invalid
            if checksum != sha.hexdigest().encode('utf-8'):
                print("Invalid WUP request")
                return False

            sub_content, mac, imei = text.decode('utf-8').split('\t')
            content += sub_content.strip()
        print("Valid WUP request, massage: {}".format(content))
        return True


def test_communicate():
    # Create three clients and a server
    user1 = Client()
    user2 = Client("naive")
    user3 = Client()
    server = Server()
    # Only register the first two clients
    server.register(user1)
    server.register(user2)
    # Sent three requests
    req1 = user1.send_request("hello world")
    req2 = user2.send_request("UVA is an iconic public institution of higher education.")
    req3 = user3.send_request("unregistered request")
    # Print the results
    print(server.process_request(req3))
    print(server.process_request(req2))
    print(server.process_request(req1))

