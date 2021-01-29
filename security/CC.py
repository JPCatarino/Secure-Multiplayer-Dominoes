from PyKCS11 import *
from PyKCS11.LowLevel import *
from datetime import date
from asn1crypto import pem

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import (padding, rsa, utils)
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import PublicFormat

import os
import sys
import OpenSSL.crypto as osc
import cryptography.x509 as x509
import requests

class CitizenCard:

    def __init__ (self):

                
        #Uncomment for Linux use
        #lib = '/usr/local/lib/libpteidpkcs11.so'

        #Uncomment for Windows use
        lib = 'C:/Windows/System32/pteidpkcs11.dll'
        
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)
        self.slots = self.pkcs11.getSlotList()


    def signData(self, data_to_sign):

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
                    return True
                except:
                    print("Verification failed")
                    return False

    def get_signature_cert(self):

        for slot in self.slots:
            if 'CARTAO DE CIDADAO' in self.pkcs11.getTokenInfo(slot).label:
                session = self.pkcs11.openSession(slot)

                certificate = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE),
                                                (CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])

                der = bytes([c.to_dict()['CKA_VALUE'] for c in certificate][0])

                cert = load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)

                session.closeSession()

                print(cert)

                return cert