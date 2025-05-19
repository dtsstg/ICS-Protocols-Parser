from .IProtocolParser import IProtocolParserChainItem
from utils import AbstractHandler


"""
['version', 'hdr_len', 'dsfield', 'dsfield_dscp', 'dsfield_ecn', 
'len', 'id', 'flags', 'flags_rb', 'flags_df', 'flags_mf', 
'frag_offset', 'ttl', 'proto', 'checksum', 'checksum_status', 
'src', 'addr', 'src_host', 'host', 
'dst', 'dst_host']
"""
class IpParser(IProtocolParserChainItem, AbstractHandler):
    def __init__(self):
        super().__init__('ip')
        
    
    def aggregate(self, packet):
        if 'ip' not in packet: return {}
        ip = packet.ip
        
        return {
            'src':ip.src,
            'dst':ip.dst,
            'ttl':int(ip.ttl)
        }


