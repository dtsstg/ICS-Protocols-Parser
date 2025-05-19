import pyshark

from aggregators import ConnectionAggregator, TypeAggregator
from utils import draw

pcap_pathes = [
    # "samples\\ICS-pcap\\Additional Captures\\4SICS-GeekLounge-151020\\4SICS-GeekLounge-151020.pcap",
    # "samples\\ICS-pcap\\EIP\\EIP-FirmwareChange\\EIP-FirmwareChange.pcap",
    # "samples\\ICS-pcap\\ETHERNET_IP\\digitalbond pcaps\\CL5000EIP-Software-Download\\CL5000EIP-Software-Download.pcap",
    # "samples/ICS-pcap/MODBUS/Modbus/Modbus.pcap"
    # "samples\\ICS-pcap\\BACNET\\BACnetARRAY-elements\\BACnetARRAY-elements.pcap"
    # "samples\\captures1_v2\\mitm\\eth2dump-mitm-change-1m-0,5h_1.pcap"
    # "samples\\captures1_v2\\clean\\eth2dump-clean-0,5h_1.pcap"
    "samples\\4SICS-GeekLounge-151020.pcap",
    "samples\\4SICS-GeekLounge-151021.pcap",
    # "samples\\4SICS-GeekLounge-151022.pcap"
]


assets, connections = set(), []

for pcap_path in pcap_pathes:
    capture = pyshark.FileCapture(input_file=pcap_path, tshark_path="D:/Wireshark/tshark.exe", keep_packets=False)
    capture.set_debug()
    # capture.load_packets()
    connection_aggregator = ConnectionAggregator()
    type_aggregator = TypeAggregator(assets)
    
    for packet in capture:
        connection_aggregator.aggregate(packet)
        assets.update(connection_aggregator.assets)
        
        type_aggregator.aggregate(packet)
    print('end capture')
    
    connection_aggregator.update_graph_nodes()
    connection_aggregator.update_connections()
    type_aggregator.update_assets()
    
    connections = connections + connection_aggregator.connections
    
    capture.close()

draw(list(assets), list(connections))



