import playground
from .pls import PLSServerFactory, PLSClientFactory
from playground.network.common import StackingProtocolFactory

pimpConnector = playground.getConnector("pimp")
pimpClientType = pimpConnector.getClientStackFactory()
pimpServerType = pimpConnector.getServerStackFactory()

PLSClientFact = StackingProtocolFactory.CreateFactoryType(pimpClientType, PLSClientFactory)
PLSServerFact = StackingProtocolFactory.CreateFactoryType(pimpServerType, PLSServerFactory)

plsConnector = playground.Connector(protocolStack=(PLSClientFactory(), PLSServerFactory()))
playground.setConnector("pls_roast", plsConnector)
#playground.setConnector("lab1_GoldenNuggetNetSec2019", pimpConnector)
