import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_credentials(address):
	if address == "":
		f = open("/home/nits/Downloads/20191_signed.cert","rb")
		cert_root = x509.load_pem_x509_certificate(f.read(), default_backend())
		f = open("/home/nits/Downloads/20191_2_signed.cert","rb")
		cert_ca = x509.load_pem_x509_certificate(f.read(), default_backend())
		f = open("/home/nits/Downloads/nithin.cert","rb")
		cert_cli = x509.load_pem_x509_certificate(f.read(), default_backend())
		f = open("/home/nits/Downloads/private_nithin.key","rb")
		private_key = serialization.load_pem_private_key(f.read(),password=b"NetSec", backend=default_backend())

		buff = []
		buff.append(cert_cli)
		buff.append(cert_ca)
		buff.append(cert_root)

		return private_key, buff

	else:
		return False
	
