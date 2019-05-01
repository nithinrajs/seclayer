import playground
from .pls import PIMPServerFactory, PIMPClientFactory

pimpConnector = playground.Connector(protocolStack=(PLSClientFactory(), PLSServerFactory()))
playground.setConnector("pls", pimpConnector)
#playground.setConnector("lab1_GoldenNuggetNetSec2019", pimpConnector)