from rsa import test_rsa, test_oaep_encode_and_decode
from communication_model import test_communicate
from attacker import test_hack

def main():
    print("*"*20, "Test for RSA", "*"*20)
    test_rsa("naive")

    print("*"*20, "Test for CCA2 attack", "*"*20)
    test_communicate()
    test_hack("naive")

    print("*"*20, "Test for OAEP", "*"*20)
    test_rsa("oaep")
    test_oaep_encode_and_decode()
    test_hack("oaep")

if __name__ == "__main__":
    main()
