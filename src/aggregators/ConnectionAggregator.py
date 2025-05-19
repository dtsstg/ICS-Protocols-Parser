from .IAggregator import IAggregator
from parsers import EthernetParser, IpParser, StpParser, ArpParser, TcpParser
from utils import Asset, Connection, possible_ttl, AssetType, broadcast_mac
import networkx as nx

from uuid import uuid4

class ConnectionAggregator(IAggregator):
    def __init__(self):
        super().__init__()
        self.assets = set()
        self.connections = []
        self.naive_connections = {}
                
        self.G = nx.DiGraph()
        
    def init_chain(self):
        self.ip_chain = EthernetParser().set_next(IpParser()).final()
        self.eth_chain = EthernetParser().final()
        self.stp_chain = EthernetParser().set_next(StpParser()).final()
        self.arp_chain = EthernetParser().set_next(ArpParser()).final()
        self.lldp_chain = EthernetParser().set_next(ArpParser()).final()
        
        self.tcp_chain = EthernetParser().set_next(TcpParser()).final()
    
    def __get_asset(self,id):
        return next((i for i in self.assets if i.get_identifier() == id), None)
    
    def __add_or_update_asset(self,payload:dict):
        id = payload.get('id')
        asset = self.__get_asset(id)
        if asset: 
            asset.update(payload)
            return asset
        else:
            mac = payload.get('mac')
            ips = payload.get('ips', set())
            asset_type = payload.get('type', AssetType.Unknown)
            tags = payload.get('tags', [])
            asset = Asset(mac=mac,ips=ips,asset_type=asset_type,tags=tags)
            self.assets.add(asset)
            return asset
        
        
    
    def parse_arp(self,data):
        opcode = data.get('opcode',{}).get('arp')
        
        for k in ['dst','src'] if opcode == 2 else ['src']:
            arp = data.get(k,{}).get('arp')
                
            if not arp: continue
                
            mac = arp.get('mac')
            ip = arp.get('ip')
            ips = set()
            if ip: ips.add(ip)
                
            payload={
                'id':mac,
                'ips':ips,
                'mac':mac,
            }
                
            self.__add_or_update_asset(payload)
                
                
        
        pass
    
    def parse_switches(self,data):
        
        if data['root'] and data['root']['stp']:
            payload = {
                'id':data['root']['stp'],
                'mac': data['root']['stp'],
                'type': AssetType.Switch,
                'tags': ['root']
            }
            asset = self.__add_or_update_asset(payload)
            self.naive_connections[frozenset(((data.get('src',{}).get('eth'),data.get('src',{}).get('ip')), (asset.mac,None)))] = None
            
        for k in ['dst','src']:
            if data[k] and data[k]['eth']:
                payload = {
                    'id':data[k]['eth'],
                    'mac':data[k]['eth'],
                    'type':AssetType.Switch
                }
                

                self.__add_or_update_asset(payload)    
    
    def parse_lldp(self,data):
        mac = data.get('src',{}).get('eth')
        print('lldp',mac)
        self.__add_or_update_asset({'id':mac,'mac':mac, 'type':AssetType.Switch})
        
    def parse_assets(self, data):
        for k in ['dst','src']:
            mac = data.get(k,{}).get('eth')
            ip = data.get(k,{}).get('ip')
            
            ips = set()
            if ip: ips.add(ip)
                        
            payload = {
                'id':mac,
                'mac':mac,
                'ips':ips
            }
            
            self.__add_or_update_asset(payload)
            
    def naive_parse_connections(self, data:dict):
        if not data or len(data) == 0: return
        self.naive_connections[frozenset((data.get(k,{}).get('eth'),data.get(k,{}).get('ip')) for k in ['dst','src'])] = data.get('ttl',{}).get('ip')
    
    def update_graph_nodes(self):
        for asset in list(self.assets):
            self.G.add_node(asset.get_identifier())
    
    def define_groups(self):
        # undirected = self.G.to_undirected()
        # subgraphs = [undirected.subgraph(c).copy() for c in nx.connected_components(undirected)]        
        # for g in subgraphs:
        #     print(g)
        pass
    
    def update_connections(self):
        # parse naive connections 1. identify assest 2. find max ttl 3. add unknown nodes
        
        # ttls = [int(x) for x in filter(lambda x:not (x == None), self.naive_connections.values())]
        # max_ttl:int = max(ttls)
        
        # limit_ttl = min(possible_ttl, key=lambda x: abs(x - max_ttl))
        
        # entries = sorted(self.naive_connections.items(), key=lambda d:limit_ttl - d[1] if d[1] else 0)
        entries = self.naive_connections.items()
        
        for src_dst, ttl in entries:
            src,dst = [self.__get_asset(a[0]) for a in list(src_dst)]
            if not src or not dst:
                print('Asset not found', src_dst)
                continue
            
            # ttl_diff:int = limit_ttl - ttl if ttl else 1
            tags = []
            # if ttl_diff == 0:
            #     tags.append('local')
            
            # if(ttl_diff <= 1):
            #     self.G.add_edge(src.get_identifier(), dst.get_identifier())
            #     connection = Connection(src,dst, ttl_diff, tags)
            #     self.connections.append(connection)
            # else:
            # self.insert_unknown_chain(src.get_identifier(), dst.get_identifier())
            self.G.add_edge(src.get_identifier(), dst.get_identifier())
            connection = Connection(src=src,dst=dst, tags=tags, ttl=ttl)
            self.connections.append(connection)            
    
    def parse_ports_info(self,data):
        flags = data.get('flags',{}).get('tcp', {})
        is_response = flags.get('syn',False) and flags.get('ack',False)
        
        if is_response:
            mac = data.get('src',{}).get('eth')
            port = data.get('port',{}).get('tcp')
            
            payload = {'id':mac, mac:'mac', 'ports': port}
    
    def insert_unknown_chain(self, src, dst, observed_ttl):  
        try:
            known_length = nx.shortest_path_length(self.G, src, dst)
        except nx.NetworkXNoPath:
            known_length = 0
        
        needed_hops = observed_ttl
        extra_hops = needed_hops - known_length - 1
        
        if extra_hops <= 0:
            return
        
        # Remove existing direct edge if it exists
        if self.G.has_edge(src, dst):
            self.G.remove_edge(src, dst)

        # Insert unknown ip_chain
        last_node = src
        for i in range(extra_hops):
            unknown = uuid4()
            
            asset = Asset(unknown=unknown)
            self.assets.add(asset)
            
            self.G.add_node(unknown, label="unknown")
            self.G.add_edge(last_node, unknown)
            
            self.connections.append(Connection(self.__get_asset(last_node),asset))
            
            last_node = unknown

        self.G.add_edge(last_node, dst)
        self.connections.append(Connection(self.__get_asset(last_node),self.__get_asset(dst)))
    
    def aggregate(self,packet):
        data = {}
        if 'ip' in packet:
            data = self.ip_chain.handle(packet)
            self.parse_assets(data)
        elif 'stp' in packet:
            data = self.stp_chain.handle(packet)
            self.parse_switches(data)

        elif 'arp' in packet:
            data = self.arp_chain.handle(packet)
            self.parse_arp(data)
            
        elif 'eth' in packet:
            data = self.eth_chain.handle(packet)
            self.parse_assets(data)
                # print(packet)
        else:
            print(packet)
        
        if 'tcp' in packet:
            data = self.tcp_chain.handle(packet)
            self.parse_ports_info(data)    
            
            # if 'lldp' in packet:
            #     data = self.lldp_chain.handle(packet)
            #     self.parse_lldp(data)
                
        self.naive_parse_connections(data)
        
        # self.update_graph_nodes()
        # self.update_connections()
        
        
        # self.define_groups()
        # return {
        #     'assets':self.assets,
        #     'connections':self.connections
        # }

            
                
        
        