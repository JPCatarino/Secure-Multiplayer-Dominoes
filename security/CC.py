from PyKCS11.LowLevel import *
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (padding, rsa, utils)
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from PyKCS11 import *
import cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from cryptography.hazmat.primitives import padding

# ------------------------------CC Authentication---------------------------------------------

class CitizenCard:

    def __init__ (self):

                
        #Uncomment for Linux use
        #lib = '/usr/local/lib/libpteidpkcs11.so'

        #Uncomment for Windows use
        lib = 'C:/Windows/System32/pteidpkcs11.dll'
        
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)
        self.slots = self.pkcs11.getSlotList()


    def signData_CC(self, data_to_sign):

        for slot in self.slots:
            if 'CARTAO DE CIDADAO' in self.pkcs11.getTokenInfo(slot).label:
                data = bytes(data_to_sign, 'utf-8')

                session = self.pkcs11.openSession(slot)

                privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

                signature = bytes(session.sign(privKey, data, Mechanism(CKM_SHA1_RSA_PKCS)))

                session.closeSession
        return signature, data

    def validateSign(self, signature, data):
        for slot in self.slots:
            if 'CARTAO DE CIDADAO' in self.pkcs11.getTokenInfo(slot).label:
                session = self.pkcs11.openSession(slot)

                pubKeyHandle = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
                
                pubKeyDer = session.getAttributeValue(pubKeyHandle, [CKA_VALUE], True)[0]

                session.closeSession

                pubKey = load_der_public_key(bytes(pubKeyDer), default_backend())

                try:
                    pubKey.verify(signature, data, PKCS1v15(), hashes.SHA1())
                    print("Verification Succeeded")
                except:
                    print("Verification failed")

       
    def authenticateCC(self, data):
        for slot in self.slots:
            if 'CARTAO DE CIDADAO' in self.pkcs11.getTokenInfo(slot).label:
                key = serialization.load_pem_public_key(data,
                                                        default_backend())
                datainbytes = bytes(str(key), 'utf-8')

                session = self.pkcs11.openSession(slot)

                privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

                pubKeyHandle = \
                    session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

                signature = bytes(session.sign(privKey, datainbytes, Mechanism(CKM_SHA1_RSA_PKCS)))

                pubKeyDer = session.getAttributeValue(pubKeyHandle, [CKA_VALUE], True)[0]

                pubKey = load_der_public_key(bytes(pubKeyDer), default_backend())

                pCC = pubKey.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                pemCC = open("public_key_CC.pem", "wb")
                pemCC.write(pCC)
                pemCC.close()
                # certificate = \
                #     session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE")])[
                #         0]
                # certDer = bytes(session.getAttributeValue(certificate, [CKA_VALUE], True)[0])
                session.closeSession()

                return signature, datainbytes  # , certDer
