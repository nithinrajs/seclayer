from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL
import os, hashlib, logging, asyncio, random

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto

PATH_TRUSTED_CERT = "/" #This is the path to the trusted cert
PATH_SELF_CERT = "/" #This is the path to our own certificate

logger = logging.getLogger('playground.__connector__.' + __name__)

class PLSPacket(PacketType):
    DEFINITION_IDENTIFIER = 'PLS.Packet'
    DEFINITION_VERSION = '1.0'
    FIELDS = [
     ('Type', STRING), # type can be Hello, KeyTransport, Finished, Data and Close.
     ('Premaster_Secret', UINT32) {OPTIONAL},
     ('Random', UINT32) {OPTIONAL},
     ('Certificate', BUFFER) {OPTIONAL},
     ('Encrypted_Data', BUFFER)]

    PLSCertificate = { # using the x.509 certificate itself.
      "Version_Number": None,
      "Issuer_Name": None,
      "Subject_Name": None,
      "Public_Key": None,
      "Public_Key_Alg": None,
      "Cert_Sign": None
    }

    @classmethod
    def HelloPacket(cls, random):
        pkt = cls()
        pkt.Type = "Hello"
        #pkt.Premaster_Secret = "" # need to sort it out
        pkt.Random = random #random.getrandbits(32) #This too
        pkt.Certificate = PLSCertificate #Should send a list
        pkt.Encrypted_Data = ""

        print("<><><><> SENT Hello Packet <><><><>")
        return pkt


    @classmethod
    def KeyPacket(cls, random):
      pkt = cls()
      pkt.Type = " KeyTransport"
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
        pkt.Random = "" #This too
        pkt.Certificate = "" #Should send a list
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
    self.pmk = 0
    self.state = ""
    SER_LISTEN = 100
    SER_HELLO_SENT = 102
    SER_SESSION_SENT = 103
    SER_FIN_SENT = 104

    CLI_HELLO_SENT = 202
    CLI_SESSION_SENT = 203
    CLI_FIN_SENT = 204


  def sendHello(self):
    self.rand = self.GenRandom()
    self.sent_rand = rand
    pkt = self.PLSPacket.HelloPacket(self.sent_rand)
    transport.write(pkt.__serialize__())
    if self.state = SER_LISTEN:
      self.state = SER_HELLO_SENT
    else:
      self.state = CLI_HELLO_SENT

  def sendPmk(self):
    self.pmk = self.Genpmk()
    pkt = self.PLSPacket.KeyPacket(self.pmk)
    transport.write(pkt.__serialize__())
    if self.state = CLI_HELLO_SENT:
      self.state = CLI_SESSION_SENT
    else:
      self.state = SER_SESSION_SENT

  def GenRandom(self):
    self.rand = random.getrandbits(32)
    return self.rand

  def Genpmk(self):
    self.pmk = random.getrandbits(32)
    return self.pmk

  def verified(cert_data):
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data) #Saving the recieved certificate
    try:
      store = crypto.X509Store()

      cert_file = open(PATH_TRUSTED_CERT, 'r')
      trusted_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
      store.add_cert(trusted_certificate)

      store_ctx = crypto.X509StoreContext(store, certificate)
      store_ctx.verify_certificate()

      return True

    except Exception as e:
      print(e)
      return False




  def data_received(self,data):
    self.deserializer.update(data)
    for pkt in self.deserializer.nextPackets():
      if pkt.Type == "Hello" and self.state == SER_LISTEN:
        # Call for certificate verification
        if(Verified):
          self.sendHello()
          self.state = SER_HELLO_SENT

      elif pkt.Type == "Hello" and self.state == CLI_HELLO_SENT:
        # Do something else process the packet and prepare for session key
        pass

      elif pkt.Type == "KeyTransport" and self.state == SER_HELLO_SENT:
        # get the packet
        #decrypt the packet
        # store the premaster key
        #send Pmk to client signed with clients public key

      elif pkt.Type == "KeyTransport" and self.state == CLI_SESSION_SENT:
        # decrypt with private key
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
