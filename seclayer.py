from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL
import os, hashlib, logging, asyncio, random

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization 
from OpenSSL import crypto


PATH_TRUSTED_CERT = "/home/nits/trusted_certs/CA_cert.cert" #This is the path to the trusted cert

#PATH_SELF_CERT = "/" #This is the path to our own certificate

logger = logging.getLogger('playground.__connector__.' + __name__)

class PLSPacket(PacketType):
    DEFINITION_IDENTIFIER = 'PLS.Packet'
    DEFINITION_VERSION = '1.0'
    FIELDS = [
     ('Type', STRING), # type can be Hello, KeyTransport, Finished, Data and Close.
     ('Premaster_Secret', BUFFER) {OPTIONAL},
     ('Random', BUFFER) {OPTIONAL},
     ('Certificate', BUFFER) {OPTIONAL},
     ('Encrypted_Data', BUFFER)]
"""
    PLSCertificate = { # using the x.509 certificate itself.
      "Version_Number": None,
      "Issuer_Name": None,
      "Subject_Name": None,
      "Public_Key": None,
      "Public_Key_Alg": None,
      "Cert_Sign": None
    }"""

    @classmethod
    def HelloPacket(cls, random, path):
        pkt = cls()
        pkt.Type = "Hello"
        pkt.Random = random #random.getrandbits(32) #This too
        f = open(path,"rb")
        pkt.Certificate = f.read() #Should send a list
        #pkt.Certificate = certificate
        pkt.Encrypted_Data = ""
        print("<><><><> SENT Hello Packet <><><><>")
        return pkt


    @classmethod
    def KeyPacket(cls, random):
      pkt = cls()
      pkt.Type = "KeyTransport"
      pkt.Premaster_Secret = random # need to sort it out
      #pkt.Random = random #This too
      #pkt.Certificate = PLSCertificate #Should send a list
      pkt.Encrypted_Data = ""

      print("<><><><> SENT Key Packet <><><><>")
      return pkt


    @classmethod
    def FinPacket(cls):
        pkt = cls()
        pkt.Type = "Finished"
        #pkt.Premaster_Secret = "" # need to sort it out
        #pkt.Random = "" #This too
        #pkt.Certificate = "" #Should send a list
        pkt.Encrypted_Data = ""

        print("<><><><> SENT Finished Packet <><><><>")
        return pkt

   """
   @classmethod
   def DataPacket(cls):
        pkt = cls()
        pkt.Type = "Data"
        pkt.Premaster_Secret = "" # need to sort it out
        pkt.Random = 0 #This too
        #pkt.Certificate = "" #Should send a list
        pkt.Encrypted_Data = ""

        print("<><><><> SENT Data Packet <><><><>")
        return pkt """

    @classmethod
    def ClosePacket(cls):
        pkt = cls()
        pkt.Type = "Close"
        pkt.Premaster_Secret = "" # need to sort it out
        #pkt.Random = 0 #This too
        #pkt.Certificate = "" #Should send a list
        pkt.Encrypted_Data = ""
        print("<><><><> SENT Close Packet <><><><>")
        return pkt

class PLSTransport(StackingTransport):
    def __init__(self, protocol, lower_transport):
        super().__init__(lower_transport)
        self._protocol = protocol
        self._closed = False

    def write(self, data):
        #self._protocol._sendEncData(data)
        pass


    def close(self):   # Closing the connection check
        if self._closed:
            return
        self._closed = True
        self._protocol.higherProtocol().connection_lost(None)
        self._protocol.close()

class PLSProtocol(StackingProtocol):
  def __init__(self):
    self.sent_rand = 0 #random.getrandbits(32)
    self.recv_rand = 0
    self.pmk = 0
    self.recv_pmk = 0
    self.state = None
    self.pubkey = None
    self.recv_cert = None
    self.masterkey = None

    SER_LISTEN = 100
    SER_HELLO_SENT = 102
    SER_PMK_SENT = 103
    SER_FIN_SENT = 104

    CLI_HELLO_SENT = 202
    CLI_PMK_SENT = 203
    CLI_FIN_SENT = 204


  def sendHello(self):
    self.rand = self.GenRandom()
    self.sent_rand = rand
  
    if self.state = SER_LISTEN:
      path = "/home/nits/trusted_certs/bank_cert.cert"
      pkt = self.PLSPacket.HelloPacket(self.sent_rand, path)
      transport.write(pkt.__serialize__())
      self.state = SER_HELLO_SENT
    else:
      path = "/home/nits/trusted_certs/client_cert.cert"
      pkt = self.PLSPacket.HelloPacket(self.sent_rand, path)
      transport.write(pkt.__serialize__())
      self.state = CLI_HELLO_SENT

  def sendPmk(self, pmk = 0):
    if pmk == 0:
      self.pmk = self.Genpmk()
    else:
      self.pmk = pmk
      
    encrypt_pmk = self.pubkey.encrypt(self.pmk, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None)
    )

    if self.state = CLI_HELLO_SENT:
      pkt = self.PLSPacket.KeyPacket(encrypt_pmk)
      transport.write(pkt.__serialize__())
      self.state = CLI_PMK_SENT
    else:
      pkt = self.PLSPacket.KeyPacket(encrypt_pmk)
      transport.write(pkt.__serialize__())
      self.state = SER_PMK_SENT


  def recvPmk(self, encrypt_pmk):

    if self.state = SER_HELLO_SENT:
      
      PATH = "/home/nits/trusted_certs/private/bank_cert.pem"
      f = open(PATH,"rb")
      private_key = serialization.load_pem_private_key(
        f.read(),
        password="testbank",
        backend=default_backend())

      self.recv_pmk = private_key.decrypt(encrypt_pmk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

      self.sendPmk(self.recv_pmk)

    else:
      PATH = "/home/nits/trusted_certs/private/bank_cert.pem"
      f = open(PATH,"rb")
      private_key = serialization.load_pem_private_key(f.read(), password="testbank", backend=default_backend())
      self.recv_pmk = private_key.decrypt(encrypt_pmk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))

      if self.pmk == self.recv_pmk:
        self.KDF()




  def GenRandom(self):
    self.rand = random.getrandbits(32)
    return self.rand

  def Genpmk(self):
    self.pmk = random.getrandbits(32)
    return self.pmk

  def verified(cert):
    #certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data) #Saving the recieved certificate
    try:
      store = crypto.X509Store()

      cert_file = open(PATH_TRUSTED_CERT, 'r')
      trusted_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
      store.add_cert(trusted_certificate)

      store_ctx = crypto.X509StoreContext(store, cert)
      store_ctx.verify_certificate()

      return True

    except Exception as e:
      print(e)
      return False

  def ProcessCert(self,cert):
    #self.pubkey = cert.get_pubkey()
    self.recv_cert = cert
    self.pubkey = self.recv_cert.get_pubkey()
    self.pubkey = pubkey.to_cryptography_key()


  def KDF(self):
        print (self.sent_rand)
        print (self.recv_rand)
        if "CLI" in self.state:
          self.masterkey = self.sent_rand
          self.masterkey += self.recv_rand #self.server_rand
        else:
          self.masterkey = self.recv_rand #self.server_rand
          self.masterkey += self.sent_rand

        self.masterkey += self.PMK
        kdf = HKDF(algorith = hashes.SHA256(), salt = b'', info=None, length= 48, backend= default_backend())
        gen = kdf.derive(self.masterkey)

        self.client_write_key = gen[0:16]
        self.server_write_key = gen[16:32]
        self.client_iv = gen[32:40]
        self.server_iv = gen[40:48]
    



  def data_received(self,data):
    self.deserializer.update(data)
    for pkt in self.deserializer.nextPackets():
      if pkt.Type == "Hello" and self.state == SER_LISTEN:
        # Call for certificate verification
        cert = pkt.Certificate
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert) 
        if(verified(certificate)):
          self.recv_rand = pkt.random
          self.ProcessCert(certificate)
          self.sendHello()
          #self.state = SER_HELLO_SENT

      elif pkt.Type == "Hello" and self.state == CLI_HELLO_SENT:
        # Do something else process the packet and prepare for session key
        cert = pkt.Certificate
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        if(verified(certificate)):
          self.recv_rand = pkt.random
          self.ProcessCert(cert)
          self.sendPmk() # Send PMK
  

      elif pkt.Type == "KeyTransport" and self.state == SER_HELLO_SENT:
        encrypt_pmk = pkt.Premaster_Secret
        recvPmk(encrypt_pmk) #decrypt the packet
        # store the premaster key
        #send Pmk to client signed with clients public key

      elif pkt.Type == "KeyTransport" and self.state == CLI_PMK_SENT:
        encrypt_pmk = pkt.Premaster_Secret
        recvPmk(encrypt_pmk)# decrypt with private key
        #check if the session key remained same as sent
        #Prepare tp sent fin

  def sendFin(self):
    pass

  def sendClose(self):
    pass

 

class PLSClientProtocol(PimpBaseProtocol):

  def connection_made(self, transport):
    super().connection_made(transport)
    self.PLSProtocol.sendHello()

class PLSServerProtocol(PimpBaseProtocol):

  def connection_made(self, transport):
    super().connection_made(transport)
    self.state = SER_LISTEN

PLSClientFactory = StackingProtocolFactory.CreateFactoryType(PLSClientProtocol)
PLSServerFactory = StackingProtocolFactory.CreateFactoryType(PLSServerProtocol)
