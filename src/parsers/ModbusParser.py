from .IProtocolParser import IProtocolParserChainItem
from utils import AbstractHandler


"""
{'modbus.func_code': '6', 'modbus.request_frame': '59209', 
'modbus.response_time': '0.017786000', 'modbus.reference_num': '6', 
'modbus.data': '00:1e'}
"""
class ModbusParser(IProtocolParserChainItem, AbstractHandler):
    def __init__(self):
        super().__init__('modbus')
        
    
    def aggregate(self, packet):
        if 'modbus' not in packet or 'tcp' not in packet: return {}
        
        modbus = packet.modbus._all_fields
        tcp = packet.tcp._all_fields

        return {
            'code': modbus.get('modbus.func_code'),
            'data': modbus.get('modbus.data'),
            'type': 'res' if tcp.get('tcp.srcport') == '502' else 'req'
            
        }


