from .IProtocolParser import IProtocolParserChainItem
from utils import AbstractHandler


"""

"""
class LldpParser(IProtocolParserChainItem, AbstractHandler):
    def __init__(self):
        super().__init__('lldp')
        
    
    def aggregate(self, packet):
        if 'lldp' not in packet: return {}
        lldp = packet.eth._all_fields
        
        return {
            'chassis': lldp.get('lldp.chassis.id.mac'),
            'port': lldp.get('lldp.port.id')
        }


