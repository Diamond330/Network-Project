import utils, random
from Crypto.Cipher import AES
from communication_model import WUP_request
import socket

class Hacker(object):
    def __init__(self):
        self.mac = str(random.randint(1000000, 9999999))
        self.imei = str(random.randint(1000000, 9999999))

    def hack(self, pk, request, server):
        # split info
        n, e = pk
        id, C, _ = request[0]

        # start hacking
        hacking_aes = 0
        for i in range(127, -1, -1):
            C_b = [c * ((1 << i * e) % n) % n for c in C]
            aes_key = utils.bit_mask(128) & (hacking_aes << i)
            aes_session = AES.new(aes_key.to_bytes(16, 'big'))
            wups = WUP_request("Hack processing", self.mac, self.imei)
            encrypted_wups = [aes_session.encrypt(wup) for wup in wups]
            req = [(id, C_b, wup) for wup in encrypted_wups]
            hacking_aes = (1 - server.process_request(req)) << (127 - i) | hacking_aes

        # recover text
        aes_session = AES.new(hacking_aes.to_bytes(16, 'big'))
        original_text = ""
        for _, _, req in request:
            de_text = aes_session.decrypt(req)
            content = de_text[:-64]
            C = content.decode('utf-8').split('\t')[0]
            original_text += C.strip()
        print("The original text is: {}".format(original_text))

        return hacking_aes