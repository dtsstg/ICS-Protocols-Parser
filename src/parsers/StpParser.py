from .IProtocolParser import IProtocolParserChainItem
from utils import AbstractHandler


"""
['protocol', 'version', 'type', 'flags', 'flags_tcack', 'flags_agreement', 
'flags_forwarding', 'flags_learning', 'flags_port_role', 'flags_proposal', 'flags_tc', 
'', 'root_prio', 'root_ext', 'root_hw', 'root_cost', 'bridge_prio', 'bridge_ext', 
'bridge_hw', 'port', 'msg_age', 'max_age', 'hello', 'forward', 'version_1_length']
"""
class StpParser(IProtocolParserChainItem, AbstractHandler):
    def __init__(self):
        super().__init__('stp')
        
    
    def aggregate(self, packet):
        if 'stp' not in packet: return {}
        stp = packet.stp._all_fields
        return {
            'root': str(stp.get('stp.root.hw'))
        }


