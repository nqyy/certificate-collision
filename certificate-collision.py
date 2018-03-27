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


from fractions import gcd

# the function returning two pairs of p and q
def functiongo(b1, b2, e=65537):
    twopower = 2 ** 1024
    while (1):
        p1 = number.getPrime(501)
        p2 = number.getPrime(501)
        if gcd(e, p1-1) == 1 and gcd(e, p2-1) == 1: break #check e coprime with p1-1 & p2-1
    #chinese

    b0 = ((-b1 * twopower) * number.inverse(p2, p1) * p2 + (-b2 * twopower) * number.inverse(p1, p2) * p1) % (p1*p2)
    print b0
    #third
    k = 0
    while(1):
#        print "round ", k
        b =  b0 + k * p1 * p2
        if b >= twopower :
            #=====================================
            k = 0
            while (1):
                p1 = number.getPrime(501)
                p2 = number.getPrime(501)
                if gcd(e, p1-1) == 1 and gcd(e, p2-1) == 1:
                    break
            #chinese remainder therom
            b0 = ((-b1 * twopower) * number.inverse(p2, p1) * p2 + (-b2 * twopower) * number.inverse(p1, p2) * p1) % (p1*p2)
            continue
            #=====================================
        q1 = (b1 * twopower + b)/p1
        q2 = (b2 * twopower + b)/p2
        if number.isPrime(q1) and number.isPrime(q2) and gcd(e, q1-1) == 1 and gcd(e, q2-1) == 1:
            break
        k += 1

    return p1, q1, p2, q2


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
def make_cert(netid, pubkey, ca_key = ECE422_CA_KEY, serial= 0x4e41f289eb7b92ea728cd5b54182a7f43d405243):
    
    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(datetime.datetime(2017, 3, 1))
    builder = builder.not_valid_after (datetime.datetime(2017, 3,27))
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, unicode(netid)),
        x509.NameAttribute(NameOID.PSEUDONYM, u'unused' + 'a'* 59),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Illinois'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'ece422'),
]))
    builder = builder.serial_number(serial)
    builder = builder.public_key(pubkey)
    cert = builder.sign(private_key=ECE422_CA_KEY, algorithm=hashes.MD5(), backend=default_backend())
    
    print len(cert.tbs_certificate_bytes[:-261])
    with open("prefix", 'wb') as f:
        f.write(cert.tbs_certificate_bytes[:-261])
    
    b1 = 59917229775954035151098037641066339807034006616375244391316545817366254283797665526651697518679344310941315028717224191970347436363462090521913169729198890148085675929148628576173492681443197445442465024344220165691529373767133115926325294572379297541201116261139259492848254070104639621634429353905470384753     #from fastcoll
    b2 = 59917229775954035151098037641066339807034006616375244391316545817366254283797665526651697518679344310941315028717224191970347436363462090521913169729638237198334034950907470227314701762733277299499815904700306398884711039468783683834173043126186620602231482045005406744109897761949355550754842730172644665969     #from fastcoll
    
    p1, q1, p2, q2 = functiongo(b1, b2)
    print p1
    print q1
    print p2
    print q2

    privkey1, pubkey1 = make_privkey(p1, q1)
    privkey2, pubkey2 = make_privkey(p2, q2)
    
    print pubkey1
    print pubkey2
    
    builder1 = x509.CertificateBuilder()
    builder1 = builder1.not_valid_before(datetime.datetime(2017, 3, 1))
    builder1 = builder1.not_valid_after (datetime.datetime(2017, 3,27))
    builder1 = builder1.subject_name(x509.Name([
                                                x509.NameAttribute(NameOID.COMMON_NAME, unicode(netid)),
                                                x509.NameAttribute(NameOID.PSEUDONYM, u'unused'),
                                                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
                                                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Illinois'),
                                                ]))
    builder1 = builder1.issuer_name(x509.Name([
                                                   x509.NameAttribute(NameOID.COMMON_NAME, u'ece422'),
                                                   ]))
    builder1 = builder1.serial_number(serial)
    builder1 = builder1.public_key(pubkey1)
    cert1 = builder1.sign(private_key=ECE422_CA_KEY, algorithm=hashes.MD5(), backend=default_backend())
    
    
    
    builder2 = x509.CertificateBuilder()
    builder2 = builder2.not_valid_before(datetime.datetime(2017, 3, 1))
    builder2 = builder2.not_valid_after (datetime.datetime(2017, 3,27))
    builder2 = builder2.subject_name(x509.Name([
                                                x509.NameAttribute(NameOID.COMMON_NAME, unicode(netid)),
                                                x509.NameAttribute(NameOID.PSEUDONYM, u'unused'),
                                                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
                                                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Illinois'),
                                                ]))
    builder2 = builder2.issuer_name(x509.Name([
                                                   x509.NameAttribute(NameOID.COMMON_NAME, u'ece422'),
                                                   ]))
    builder2 = builder2.serial_number(serial)
    builder2 = builder2.public_key(pubkey2)
    cert2 = builder2.sign(private_key=ECE422_CA_KEY, algorithm=hashes.MD5(), backend=default_backend())

    return cert1, cert2

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
    cert1, cert2 = make_cert(netid, pubkey)
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
