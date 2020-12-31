from PyKCS11.LowLevel import CKA_CLASS, CKO_PRIVATE_KEY, CKA_LABEL, CKM_SHA1_RSA_PKCS, CKO_CERTIFICATE, CKA_VALUE, CKO_PUBLIC_KEY
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (padding, rsa, utils)
from PyKCS11 import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from cryptography.hazmat.primitives import padding
pkcs11 = PyKCS11Lib()
pkcs11.load('/usr/local/lib/libpteidpkcs11.so')
slots = pkcs11.getSlotList()


# ------------------------------CC Authentication---------------------------------------------

def authenticateCC(data):
    # slots = pkcs11.getSlotList()
    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            key = serialization.load_pem_public_key(data,
                                                    default_backend())
            datainbytes = bytes(str(key), 'utf-8')

            session = pkcs11.openSession(slot)

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


def validateCC(signature, datainbytes, pubKey):
    # slots = pkcs11.getSlotList()
    # for slot in slots:
    #     if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
    #         session = pkcs11.openSession(slot)
    #         pubKeyHandle = \
    #             session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
    #
    #         pubKeyDer = session.getAttributeValue(pubKeyHandle, [CKA_VALUE], True)[0]
    #
    #         session.closeSession()
    #
    #         pubKey = load_der_public_key(bytes(pubKeyDer), default_backend())
    with open(pubKey, "rb") as kf:
        key = serialization.load_pem_public_key(kf.read(),
                                                default_backend())
        try:
            key.verify(signature, datainbytes, padding.PKCS1v15(), hashes.SHA1())
            print('Verification suceeded')
        except:
            print('Verification failed')

