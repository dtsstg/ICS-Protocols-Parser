from .IProtocolParser import IProtocolParserChainItem
from utils import AbstractHandler


"""
{'tcp.srcport': '502', 'tcp.dstport': '52162', 'tcp.port': '502', 
'tcp.stream': '4220', 'tcp.completeness': '15', 'tcp.len': '12', 
'tcp.seq': '1', 'tcp.seq_raw': '259981897', 'tcp.nxtseq': '13', 
'tcp.ack': '13', 'tcp.ack_raw': '1588548110', 'tcp.hdr_len': '20', 
'tcp.flags': '0x0018', 'tcp.flags.res': '0', 'tcp.flags.ns': '0', 
'tcp.flags.cwr': '0', 'tcp.flags.ecn': '0', 'tcp.flags.urg': '0', 
'tcp.flags.ack': '1', 'tcp.flags.push': '1', 'tcp.flags.reset': '0', 
'tcp.flags.syn': '0', 'tcp.flags.fin': '0', 'tcp.flags.str': '·······AP···', 
'tcp.window_size_value': '8712', 'tcp.window_size': '8712', 
'tcp.window_size_scalefactor': '-2', 'tcp.checksum': '0xe21b', 
'tcp.checksum.status': '2', 'tcp.urgent_pointer': '0', '': 'Timestamps', 
'tcp.time_relative': '0.031842000', 'tcp.time_delta': '0.000816000', 
'tcp.analysis': 'SEQ/ACK analysis', 'tcp.analysis.initial_rtt': 
'0.010269000', 'tcp.analysis.bytes_in_flight': '12', 
'tcp.analysis.push_bytes_sent': '12', 
'tcp.payload': '00:01:00:00:00:06:01:06:00:06:00:1e', 'tcp.pdu.size': '12'}
"""
class TcpParser(IProtocolParserChainItem, AbstractHandler):
    def __init__(self):
        super().__init__('tcp')
        
    
    def aggregate(self, packet):        
        if 'tcp' not in packet: return {}
        
        tcp = packet.tcp._all_fields
        
        return {
            'src': tcp.get('tcp.srcport'),
            'dst': tcp.get('tcp.dstport'),
            'stream': tcp.get('tcp.stream'),
            'flags': {
                'res': tcp.get('tcp.flags.res', '0') == '1',
                'ns': tcp.get('tcp.flags.ns', '0') == '1',
                'cwr': tcp.get('tcp.flags.cwr', '0') == '1',
                'ecn': tcp.get('tcp.flags.ecn', '0') == '1',
                'urg': tcp.get('tcp.flags.urg', '0') == '1',
                'ack': tcp.get('tcp.flags.ack', '0') == '1',
                'push': tcp.get('tcp.flags.push', '0') == '1',
                'reset': tcp.get('tcp.flags.reset', '0') == '1',
                'syn': tcp.get('tcp.flags.syn', '0') == '1',
                'fin': tcp.get('tcp.flags.fin', '0') == '1'
                
                },
        }


