import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
PATH = "/home/nithin/seclayer/pcert/"
def get_credentials(address):
	#if address == "2019.2.1.0":
		f = open(PATH + "20191_signed.cert","rb")
		cert_root = x509.load_pem_x509_certificate(f.read(), default_backend())
		ser_cert_root = cert_root.public_bytes(encoding=serialization.Encoding.PEM)
		f = open(PATH + "20191_2_signed.cert","rb")
		cert_ca = x509.load_pem_x509_certificate(f.read(), default_backend())
		ser_cert_ca = cert_ca.public_bytes(encoding=serialization.Encoding.PEM)
		f = open(PATH + "nithin.cert","rb")
		cert_cli = x509.load_pem_x509_certificate(f.read(), default_backend())
		ser_cert_cli = cert_cli.public_bytes(encoding=serialization.Encoding.PEM)
		f = open(PATH+"private_nithin.key","rb")
		private_key = serialization.load_pem_private_key(f.read(),password=b"NetSec", backend=default_backend())

		buff = []
		buff.append(ser_cert_cli)
		buff.append(ser_cert_ca)
		buff.append(ser_cert_root)

		return private_key, buff

	#else:
	#	return False
	
