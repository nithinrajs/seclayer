from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL
import os, hashlib, logging, asyncio
logger = logging.getLogger('playground.__connector__.' + __name__)

class PLSPacket(PacketType):
    DEFINITION_IDENTIFIER = 'PLS.Packet'
    DEFINITION_VERSION = '1.0'
    FIELDS = [
     ('Type', STRING),
     ('Session_Key', STRING),
     ('Random', UINT31),
     ('Certificate', BUFFER),
     ('Encrypted_Data', BUFFER),
     ('Signature', STRING)]


class PLSTransport(StackingTransport):
    def __init__(self, protocol, lower_transport):  #Why is he calling lower_transport??
        super().__init__(lower_transport)
        self._protocol = protocol
        self._closed = False

    def write(self, data):
        self._protocol._sendData(data)

    def close(self):   # Clossing the connection check
        if self._closed:
            return
        self._closed = True
        self._protocol.higherProtocol().connection_lost(None)
        self._protocol.close()

class PLSBaseProtocol(StackingProtocol):
  pass

class PLSClientProtocol(PimpBaseProtocol):
  pass

class PLSServerProtocol(PimpBaseProtocol):
  pass
