from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL
import os, hashlib, logging, asyncio, random
logger = logging.getLogger('playground.__connector__.' + __name__)

class PLSPacket(PacketType):
    DEFINITION_IDENTIFIER = 'PLS.Packet'
    DEFINITION_VERSION = '1.0'
    FIELDS = [
     ('Type', STRING), # type can be Hello, Finished, Data and Close.
     ('Session_Key', STRING),
     ('Random', UINT31),
     ('Certificate', BUFFER),
     ('Encrypted_Data', BUFFER),
     ('Signature', STRING)]

    PLSCertificate = {
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
        #pkt.Session_Key = "" # need to sort it out
        pkt.Random = random #random.getrandbits(32) #This too
        pkt.Certificate = PLSCertificate #Should send a list
        #pkt.Encrypted_Data = ""
        #pkt.Signature = "" #This too
        print("<><><><> SENT Hello Packet <><><><>")
        return pkt

    def FinPacket(cls):
        pkt = cls()
        pkt.Type = "Finished"
        pkt.Session_Key = "" # need to sort it out
        pkt.Random = 0 #This too
        #pkt.Certificate = "" #Should send a list
        pkt.Encrypted_Data = ""
        pkt.Signature = "" #This too
        print("<><><><> SENT Finished Packet <><><><>")
        return pkt

    def DataPacket(cls):
        pkt = cls()
        pkt.Type = "Data"
        pkt.Session_Key = "" # need to sort it out
        pkt.Random = 0 #This too
        #pkt.Certificate = "" #Should send a list
        pkt.Encrypted_Data = ""
        pkt.Signature = "" #This too
        print("<><><><> SENT Data Packet <><><><>")
        return pkt

    def ClosePacket(cls):
        pkt = cls()
        pkt.Type = "Close"
        pkt.Session_Key = "" # need to sort it out
        #pkt.Random = 0 #This too
        #pkt.Certificate = "" #Should send a list
        pkt.Encrypted_Data = ""
        pkt.Signature = "" #This too
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
  

class PLSClientProtocol(PimpBaseProtocol):
  def connection_made(self, transport):
    super().connection_made(transport)
    self._state = self._handle_listening

class PLSServerProtocol(PimpBaseProtocol):
  def connection_made(self, transport):
    super().connection_made(transport)
    self._state = self._handle_listening

PLSClientFactory = StackingProtocolFactory.CreateFactoryType(PLSClientProtocol)
PLSServerFactory = StackingProtocolFactory.CreateFactoryType(PLSServerProtocol)
