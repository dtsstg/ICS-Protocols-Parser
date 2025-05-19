from .IProtocolParser import IProtocolParserChainItem
from utils import AbstractHandler


"""
['dst', 'dst_resolved', 'dst_oui', 'dst_oui_resolved', 'addr', 
'addr_resolved', 'addr_oui', 'addr_oui_resolved', 'dst_lg', 'lg', 
'dst_ig', 'ig', 'src', 'src_resolved', 'src_oui', 'src_oui_resolved', 
'src_lg', 'src_ig', 'type']
"""
class EthernetParser(IProtocolParserChainItem, AbstractHandler):
    def __init__(self):
        super().__init__('eth')
        
    
    def aggregate(self, packet):
        if 'eth' not in packet: return {}
        eth = packet.eth
                
        return {
            'dst': eth.dst,
            'src': eth.src
        }


