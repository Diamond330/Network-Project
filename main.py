from rsa import test_rsa, test_oaep_encode_and_decode
from communication_model import test_communicate
from communication_model import WUP_request, Client, Server
from Hacker import Hacker

def main():
    # print("*"*20, "Test for RSA", "*"*20)
    # test_rsa("naive")
    #
    # print("*"*20, "Test for CCA2 attack", "*"*20)
    # test_communicate()

    # test CCA2 attack
    user1 = Client('naive')
    req = user1.send_request("no pain, no gain")
    server = Server()
    server.register(user1)
    attacker = Hacker()
    attacker.hack(user1.rsa.public_key, req, server)

    # print("*"*20, "Test for OAEP", "*"*20)
    # test_rsa("oaep")
    # test_oaep_encode_and_decode()
    # test_hack("oaep")

if __name__ == "__main__":
    main()
