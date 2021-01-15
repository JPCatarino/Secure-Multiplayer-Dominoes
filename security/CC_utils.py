from PyKCS11 import *
from PyKCS11.LowLevel import *
from datetime import date
from asn1crypto import pem

from cryptography.x509 import load_der_x509_certificate

import os
import sys
import OpenSSL.crypto as osc
import cryptography.x509 as x509
import requests

# Uncomment this if you're having trouble with module not found
sys.path.append(os.path.abspath(os.path.join('.')))
sys.path.append(os.path.abspath(os.path.join('..')))

from security.CC import CitizenCard


def validate_certificates(cf_bytes, ccerts_bytes):
    
    # Create validation context
    root = osc.X509Store()

    # Set flags
    root.set_flags(osc.X509StoreFlags.X509_STRICT)

    d = date.today()
    root.set_time(d)

    intermediate = []

    # load certificates

    if pem.detect(ccerts_bytes):
        for _, _, der_bytes in pem.unarmor(ccerts_bytes, multiple=True):
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
        
        return True

    except Exception as e:
        print('not coolio', e)
        return False



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

""" if __name__ == '__main__':
    CC = CitizenCard()
    cert = CC.get_signature_cert()
    f2 = open('CCCerts.crt', 'rb')
    f2 = f2.read()
    cert = CC.get_signature_cert()
    validate_certificates(cert, f2)
    signature, data = CC.signData("hello")
    CC.validateSign(signature, data)
    p = vlc.MediaPlayer("coolio.mp3")
    while True:
        p.play() """
