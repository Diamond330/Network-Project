import os, utils, random

from Crypto.Cipher import AES
from typing import Dict, List, Tuple
from communication_model import WUP_request, Client, Server

class Attacker(Client):
    def __init__(self):
        super(Attacker, self).__init__()

    def hack(self, public_key: Tuple[int, int], 
                   request: List[Tuple], 
                   server: Server
    ) -> int:
        victim_id, C, _ = request[0]
        n, e = public_key

        k_b = 0
        for b in range(127, -1, -1):
            C_b = [c * ((1 << b*e) % n) % n for c in C]
            aes_key = utils.bit_mask(128) & (k_b << b)
            aes = AES.new(aes_key.to_bytes(16, 'big'))
            wups = WUP_request("Hack processing", self.mac, self.imei)
            encrypted_wups = [aes.encrypt(wup) for wup in wups]
            req = [(victim_id, C_b, wup) for wup in encrypted_wups]
            k_b = (1-server.process_request(req)) << (127-b) | k_b

        victim_aes = k_b
        print("hacked AES key: {}".format(victim_aes))

        aes = AES.new(victim_aes.to_bytes(16, 'big'))

        wups = WUP_request("Hacking successfully", self.mac, self.imei)
        encrypted_wups = [aes.encrypt(wup) for wup in wups]

        req = [(victim_id, C, wup) for wup in encrypted_wups]
        assert server.process_request(req) == True, "Hack failed"

        original_text = ""
        for _, _, req in request:
            decrypted_text = aes.decrypt(req)
            text, checksum = decrypted_text[:-64], decrypted_text[-64:]
            content, mac, imei = text.decode('utf-8').split('\t')
            original_text += content.strip()
        print("Decrypted Cyphertext: {}".format(original_text))

        return victim_aes


def test_hack(encode_method):
    user = Client(rsa_encode_method = encode_method)
    req = user.send_request("UVA is an iconic public institution of higher education.")

    server = Server()
    server.register(user)

    attacker = Attacker()
    attacker.hack(user.rsa.public_key, req, server)

