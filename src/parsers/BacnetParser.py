from .IProtocolParser import IProtocolParserChainItem
from utils import AbstractHandler


"""
{'bacnet.version': '1', 'bacnet.control': '0x00', 
'bacnet.control_net': '0', 'bacnet.control_res1': '0', 
'bacnet.control_dest': '0', 'bacnet.control_res2': '0', 
'bacnet.control_src': '0', 'bacnet.control_expect': '0', 
'bacnet.control_prio_high': '0', 'bacnet.control_prio_low': '0'}

{'bacapp.type': '5', 'bacapp.invoke_id': '1', 
'bacapp.confirmed_service': '12', 'bacapp.error_class': '2', 
'': 'Application Tag: Enumerated, Length/Value/Type: 1', 
'bacapp.tag_class': '0', 
'bacapp.application_tag_number': '9', 
'bacapp.LVT': '1', 'bacapp.error_code': '42'}
"""
class BacnetParser(IProtocolParserChainItem, AbstractHandler):
    def __init__(self):
        super().__init__('bacnet')
        
    
    def aggregate(self, packet):
        if 'bacnet' not in packet: return {}
        
        bacnet = packet.bacnet._all_fields
        bacapp = packet.bacapp._all_fields
        
        return {
            # 'vendor':,
            # 'id':,
            # 'firmaware':,
            # 'name':,
            # 'description':,
            # 'location':,
            # 'fdt':,
            # 'ip':,
        }


