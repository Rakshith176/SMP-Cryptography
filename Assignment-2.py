import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

backend = default_backend()


# Class Declaration
class Communication:
    #  Private variables used
    __publickey = None
    __privatekey = None
    __iv = None
    __pempublic = None
    __symmentrickey = None
    __cipher = None
    __message = None
    __pemprivate = None
    __usableprivatekey = None

    # Public variables used
    recieveriv = None
    ivCipher = None
    recieversymmentrickey = None
    symmentrickeyCipher = None
    recievercipher = None
    ciphermessage = None
    usablepublickey = None
    recieverpublickey = None
    signature = None

    # functions used
    # Function to generate keys
    def generateKeys(self):
        __privatekey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        __publickey = __privatekey.public_key()
        __pemprivate = __privatekey.private_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                  encryption_algorithm=serialization.NoEncryption())
        __pempublic = __publickey.public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.__usableprivatekey = serialization.load_pem_private_key(__pemprivate, password=None,
                                                                     backend=default_backend())
        self.usablepublickey = serialization.load_pem_public_key(__pempublic, backend=default_backend())

    # Function to pad the inputted msg
    def padding(self, msg):
        msg += " " * (32 - len(msg) % 32)
        return msg

    # Function to Send the message
    def sendMessage(self, reciecerpublickey):
        __iv = os.urandom(16)
        __symmentrickey = os.urandom(32)
        __cipher = Cipher(algorithms.AES(__symmentrickey), modes.CBC(__iv), backend=backend)
        __message = self.padding((input("Enter your Msg: ")))
        encryptor = __cipher.encryptor()
        self.ciphermessage = encryptor.update(__message.encode('ascii')) + encryptor.finalize()
        self.symmentrickeyCipher = reciecerpublickey.encrypt(__symmentrickey,
                                                             padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                          algorithm=hashes.SHA256(), label=None))
        self.ivCipher = reciecerpublickey.encrypt(__iv, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(), label=None))
        signaturemsg = b"A message I want to sign"
        self.signature = self.__usableprivatekey.sign(signaturemsg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                                salt_length=padding.PSS.MAX_LENGTH),
                                                      hashes.SHA256())

    # Function to receive the  message
    def recieveMessage(self, senderpublickey, symmentrickeyCipher, ivCipher, signature):
        self.recieversymmentrickey = self.__usableprivatekey.decrypt(symmentrickeyCipher, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        self.recieveriv = self.__usableprivatekey.decrypt(ivCipher,
                                                          padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                       algorithm=hashes.SHA256(), label=None))
        checkmessage = b"A message I want to sign"
        senderpublickey.verify(signature, checkmessage,
                               padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                               hashes.SHA256())

    # Function to Output the received msg
    def decryptRecievedMsg(self, recieversymmentrickey, reciveriv, ct):
        recievercipher = Cipher(algorithms.AES(recieversymmentrickey), modes.CBC(reciveriv), backend=backend)
        decryptor = recievercipher.decryptor()
        decryptedmessage = decryptor.update(ct) + decryptor.finalize()
        print(f'Message recieved : {decryptedmessage.decode("ascii")}')


alice = Communication()
bob = Communication()

print('Opitons:')
print("Enter 1 -> Generate Alice's pair of public and private keys")
print("Enter 2 -> Generate bob's's pair of public and private keys")
print("Enter 3 -> Send a message from Alice to Bob ")
print("Enter 4 -> Receive the message from Alice(to Bob) and Print it")
print("Enter 5 -> Send a message from Bob to Alice ")
print("Enter 6 -> Receive the message from Bob(to Alice) and Print it ")
print("Enter 7 -> Exit the Program")
while True:
    n = int(input("Enter your option: "))
    if n == 1:
        alice.generateKeys()
        print("Alice's pair of keys created successfully...")
    if n == 2:
        bob.generateKeys()
        print("Bob's pair of keys created successfully...")
    if n == 3:
        print("Sending message to Bob.. ")
        alice.sendMessage(bob.usablepublickey)
        print("Message sent successfully.")
    if n == 4:
        print("Receiving message from Alice...")
        bob.recieveMessage(alice.usablepublickey, alice.symmentrickeyCipher, alice.ivCipher, alice.signature)
        print("Decrypting and Printing the message...")
        bob.decryptRecievedMsg(bob.recieversymmentrickey, bob.recieveriv, alice.ciphermessage)
    if n == 5:
        print("Sending message to alice...")
        bob.sendMessage(alice.usablepublickey)
        print("Message sent successfully.")
    if n == 6:
        print("Receiving messag from Bob... ")
        alice.recieveMessage(bob.usablepublickey, bob.symmentrickeyCipher, bob.ivCipher, bob.signature)
        print("Decrypting and Printing the message...")
        alice.decryptRecievedMsg(alice.recieversymmentrickey, alice.recieveriv, bob.ciphermessage)
    if n == 7:
        break
