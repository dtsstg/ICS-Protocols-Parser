from .IProtocolParser import IProtocolParserChainItem
from utils import AbstractHandler


"""
{'arp.hw.type': '1', 'arp.proto.type': '0x0800', 'arp.hw.size': '6', 'arp.proto.size': '4',
'arp.opcode': '2', 'arp.src.hw_mac': '00:80:f4:09:51:3b', 'arp.src.proto_ipv4': '172.27.224.250',
'arp.dst.hw_mac': '48:5b:39:64:40:79', 'arp.dst.proto_ipv4': '172.27.224.251'}
"""
class ArpParser(IProtocolParserChainItem, AbstractHandler):
    def __init__(self):
        super().__init__('arp')
        
    
    def aggregate(self, packet):
        if 'arp' not in packet: return {}
        
        arp = packet.arp._all_fields
        
        return {
            'opcode': int(arp.get('arp.opcode')),
            'src': {'mac': arp.get('arp.src.hw_mac'), 'ip': arp.get('arp.src.proto_ipv4') },
            'dst': {'mac': arp.get('arp.dst.hw_mac'), 'ip': arp.get('arp.dst.proto_ipv4') },
        }


