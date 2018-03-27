from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Util import number
import datetime
import hashlib
import base64
import os
from gmpy import *

from fractions import gcd

def functiongo(b1, b2, e=65537):
    twopower = 2 ** 1024
    while (1):
        while (1):
            p1 = number.getPrime(500)
            p2 = number.getPrime(500)
            if gcd(e, p1-1) == 1 and gcd(e, p2-1) == 1 and p1 != p2:
                break
        b0 = ((-b1 * twopower) * number.inverse(p2, p1) * p2 + (-b2 * twopower) * number.inverse(p1, p2) * p1) % (p1*p2)
        k = 0
        while (1):
            print "k: ", k
            b = b0 + p1 * p2 * k
            if b >= twopower:
                break
            q1 = (b1*twopower+b)/p1
            q2 = (b2*twopower+b)/p2
            if number.isPrime(q1) and number.isPrime(q2) and gcd(q1-1, e) == 1 and gcd(q2-1, e) == 1 :
                return p1, q1, p2, q2
            k+=1

# Utility to make a cryptography.x509 RSA key object from p and q
def make_privkey(p, q, e=65537):
    n = p*q
    d = number.inverse(e, (p-1)*(q-1))
    iqmp = rsa.rsa_crt_iqmp(p, q)
    dmp1 = rsa.rsa_crt_dmp1(e, p)
    dmq1 = rsa.rsa_crt_dmq1(e, q)
    pub = rsa.RSAPublicNumbers(e, n)
    priv = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
    pubkey = pub.public_key(default_backend())
    privkey = priv.private_key(default_backend())
    return privkey, pubkey

# The ECE422 CA Key! Your cert must be signed with this.
ECE422_CA_KEY, _ = make_privkey(10079837932680313890725674772329055312250162830693868271013434682662268814922750963675856567706681171296108872827833356591812054395386958035290562247234129L,13163651464911583997026492881858274788486668578223035498305816909362511746924643587136062739021191348507041268931762911905682994080218247441199975205717651L)

# Skeleton for building a certificate. We will require the following:
# - COMMON_NAME matches your netid.
# - COUNTRY_NAME must be US
# - STATE_OR_PROVINCE_NAME must be Illinois
# - issuer COMMON_NAME must be ece422
# - 'not_valid_before' date must must be March 1
# - 'not_valid_after'  date must must be March 27
# Other fields (such as pseudonym) can be whatever you want, we won't check them
def make_cert(netid, pubkey, ca_key = ECE422_CA_KEY, serial= 568979425052858290743461735179889102348088699689L):
    
    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(datetime.datetime(2017, 3, 1))
    builder = builder.not_valid_after (datetime.datetime(2017, 3,27))
    builder = builder.subject_name(x509.Name([
                                              x509.NameAttribute(NameOID.COMMON_NAME, unicode(netid)),
                                              x509.NameAttribute(NameOID.PSEUDONYM, u'unused' + 'a'* 60),
                                              x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
                                              x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Illinois'),
                                              ]))
                                              builder = builder.issuer_name(x509.Name([
                                                                                       x509.NameAttribute(NameOID.COMMON_NAME, u'ece422'),
                                                                                       ]))
                                              builder = builder.serial_number(serial)
                                              builder = builder.public_key(pubkey)
                                              cert = builder.sign(private_key=ECE422_CA_KEY, algorithm=hashes.MD5(), backend=default_backend())
                                              
    return cert


if __name__ == '__main__':
    import sys
    #    if len(sys.argv) < 3:
    #        print 'usage: python mp3-certbuilder <netid> <outfile.cer>'
    #        sys.exit(1)
    #    netid = sys.argv[1]
    #    outfile = sys.argv[2]
    netid = "tchi3"
    p = number.getPrime(1024)
    q = number.getPrime(1024)
    privkey, pubkey = make_privkey(p, q)
    while(1):
        cert = make_cert(netid, pubkey)
        if len(cert.tbs_certificate_bytes[:-261]) == 256:
            break
    with open("prefix", 'wb') as f:
        f.write(cert.tbs_certificate_bytes[:-261])

    os.system("./fastcoll -p prefix -o col1 col2")

col1_file = open("col1", "rb")
col1_data = col1_file.read()

col2_file = open("col2", "rb")
    col2_data = col2_file.read()
    
    b1 = int(col1_data[-128:].encode('hex'), 16)
    b2 = int(col2_data[-128:].encode('hex'), 16)
    print "b1: ", b1
    print "b2: ", b2
    p1, q1, p2, q2 = functiongo(b1, b2)
    print "p1:", p1
    print "q1:", q1
    print "p2:", p2
    print "q2:", q2
    
    privkey1, pubkey1 = make_privkey(p1, q1)
    privkey2, pubkey2 = make_privkey(p2, q2)
    
    cert1 = make_cert(netid, pubkey1)
    cert2 = make_cert(netid, pubkey2)
    
    print 'md5 of cert1.tbs_certificate_bytes:', hashlib.md5(cert1.tbs_certificate_bytes).hexdigest()
    print 'md5 of cert2.tbs_certificate_bytes:', hashlib.md5(cert2.tbs_certificate_bytes).hexdigest()
    # We will check that your certificate is DER encoded
    # We will validate it with the following command:
    #    openssl x509 -in {yourcertificate.cer} -inform der -text -noout
    outfile1 = "out1.cer"
    outfile2 = "out2.cer"
    with open(outfile1, 'wb') as f:
        f.write(cert1.public_bytes(Encoding.DER))
    with open(outfile2, 'wb') as f:
        f.write(cert2.public_bytes(Encoding.DER))
print 'try the following command: openssl x509 -in %s -inform der -text -noout' % outfile1
    print 'try the following command: openssl x509 -in %s -inform der -text -noout' % outfile2

