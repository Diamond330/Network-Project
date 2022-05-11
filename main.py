import utils
from rsa import RSA
from communication_model import WUP_request, Client, Server
from Hacker import Hacker

def main():
    ##### RSA #####
    # change encode_method to test naive and oaep

    # sizes = [512, 1024, 2048]
    # for size in sizes:
    #     r = RSA(size, encode_method='naive')
    #     pk = r.generate_key_pairs()
    #     print("Test RSA algorithm with key size {} bit".format(size))
    #     with open("test.txt", "r") as f:
    #         for text in f.readlines():
    #             text_type, text = text.strip().split('\t')
    #             if text_type != "str":
    #                 text = eval(text)
    #             ct = r.encrypt(text)
    #             pt = r.decrypt(ct, text_type)
    #             assert pt == text, "failed"
    #     print("All test passed!")

    #####Communication #####
    # user1 = Client()
    # user2 = Client("naive")
    # user3 = Client()
    # server = Server()
    #
    # server.register(user1)
    # server.register(user2)
    #
    # req1 = user1.send_request("hello world")
    # req2 = user2.send_request("UVA is an iconic public institution of higher education.")
    # req3 = user3.send_request("unregistered request")
    #
    # print(server.process_request(req3))
    # print(server.process_request(req2))
    # print(server.process_request(req1))

    ##### CCA2 attack  #####
    # change encode_method to test naive and oaep

    # user = Client('naive')
    # user = Client('oaep')
    # req = user1.send_request("no pain, no gain")
    # server = Server()
    # server.register(user)
    # attacker = Hacker()
    # attacker.hack(user.rsa.public_key, req, server)

    ##### oaep #####
    encoder = utils.DataEncoder()
    testsets = [
        ["str", "Network secruity is a interesting topic"],
        ["str", "CS6501 is a great class."],
        ["int", 34253623],
        ["int", 2342345844594389],
    ]
    for type, text in testsets:
        en_text = encoder.oaep_encode(text)
        de_text = encoder.oaep_decode(type, en_text)
        if de_text == text:
            print("success")
        else:
            print("fail")

if __name__ == "__main__":
    main()
