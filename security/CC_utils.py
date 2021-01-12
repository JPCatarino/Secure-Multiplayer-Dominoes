from PyKCS11 import *
from PyKCS11.LowLevel import *
from datetime import datetime
from asn1crypto import pem

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate


import os
import sys
import OpenSSL.crypto as osc
import cryptography.x509 as x509
import requests

lib_path = "C:\\Windows\\System32\\pteidpkcs11.dll"


def get_CC_signature_cert():
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib_path)

    slots = pkcs11.getSlotList()

    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            session = pkcs11.openSession(slot)

            certificate = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE),
                                               (CKA_LABEL, 'CITIZEN SIGNATURE CERTIFICATE')])

            der = bytes([c.to_dict()['CKA_VALUE'] for c in certificate][0])

            cert = load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)

            session.closeSession()

            print(cert)

            return cert


def load_from_url(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.content

    return None


def validate_ocsp(cert):
    print("Not implemented")


def add_crl(root, cert, base=False, delta=False):
    c = x509.load_der_x509_certificate(osc.dump_certificate(osc.FILETYPE_ASN1, cert))
    if base:
        cdp = c.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS)
    elif delta:
        cdp = c.extensions.get_extension_for_oid(x509.oid.ExtensionOID.FRESHEST_CRL)
    else:
        return

    for dpoint in cdp.value:
        for url in dpoint.full_name:
            print('\t%s' % url.value)
            crl = osc.load_crl(osc.FILETYPE_ASN1, load_from_url(url.value))
            root.add_crl(crl)


def validate_certificates():
    if len(sys.argv) < 6:
        print('Usage: blah blah')
        sys.exit(1)

    # Create validation context
    root = osc.X509Store()

    # Set flags
    root.set_flags(osc.X509StoreFlags.X509_STRICT)

    d = datetime(year=int(sys.argv[2]), month=int(sys.argv[3]), day=int(sys.argv[4]))
    root.set_time(d)

    intermediate = []

    # load certificates

    for i in range(5, len(sys.argv)):
        with open(sys.argv[i], 'rb') as cf:
            cf_bytes = cf.read()

            if pem.detect(cf_bytes):
                for _, _, der_bytes in pem.unarmor(cf_bytes, multiple=True):
                    cert = osc.load_certificate(osc.FILETYPE_ASN1, der_bytes)
                    if cert.get_subject() == cert.get_issuer():
                        root.add_cert(cert)
                    else:
                        intermediate.append(cert)
            else:
                cert = osc.load_certificate(osc.FILETYPE_ASN1, der_bytes)
                if cert.subject == cert.issuer:
                    root.add_cert(cert)
                else:
                    intermediate.append(cert)

    # load to validate

    with open(sys.argv[1], 'rb') as cf:
        cf_bytes = cf.read()

        if pem.detect(cf_bytes):
            cert = osc.load_certificate(osc.FILETYPE_PEM, cf_bytes)
        else:
            cert = osc.load_certificate(osc.FILETYPE_ASN1, cf_bytes)

    validator = osc.X509StoreContext(root, cert, intermediate)

    try:
        validator.verify_certificate()

        # Chain was built

        print('chain: ')
        chain = validator.get_verified_chain()

        # see what we have

        for cert in chain:
            for component in cert.get_subject().get_components():
                if component[0] == b'CN':
                    print(str(component[1], 'utf8'))

            for i in range(0, cert.get_extension_count()):
                if cert.get_extension(i).get_short_name() == b'authorityInfoAccess':
                    pass
                elif cert.get_extension(i).get_short_name() == b'crlDistributionPoints':
                    add_crl(root, cert, base=True)
                elif cert.get_extension(i).get_short_name() == b'freshestCRL':
                    add_crl(root, cert, delta=True)

        root.set_flags(osc.X509StoreFlags.CRL_CHECK_ALL)

        validator.verify_certificate()
        print('coolio')
    except Exception as e:
        print('not coolio', e)


if __name__ == '__main__':
    validate_certificates()