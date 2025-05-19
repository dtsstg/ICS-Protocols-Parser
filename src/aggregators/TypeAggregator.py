from .IAggregator import IAggregator
from parsers import CipParser, EthernetParser, IpParser, TcpParser, ModbusParser, BacnetParser

from utils import Asset, AssetType, broadcast_mac, ports

class TypeAggregator(IAggregator):
    def __init__(self, assets:set):
        super().__init__()
        
        self.assets = assets
    
    def __get_asset(self,id):
        return next((i for i in self.assets if i.get_identifier() == id), None)
    
    
    def init_chain(self):
        self.modbus_chain = EthernetParser().set_next(IpParser()).set_next(TcpParser()).set_next(ModbusParser()).final()
        self.cip_chain = EthernetParser().set_next(IpParser()).set_next(TcpParser()).set_next(CipParser()).final()
        self.bacnet_chain = EthernetParser().set_next(IpParser()).set_next(BacnetParser()).final()

    
    def update_tcp_service_tags(self,data):
        mac = data.get('src', {}).get('eth')
        asset = self.__get_asset(mac)
        
        if not asset: return
        
        _ports = list(asset.ports)
        
        tags = []
        
        for port in _ports:
            name = ports[port]
            tags.append(name)
            
        asset.update({'tags': tags})
            
   
    # dnp3 the same but defines RTU
    # profibus: master is plc and slave is control system
    def parse_modbus(self,data):
        _type = data.get('type',{}).get('modbus')
        mac = data.get('src', {}).get('eth')
        asset = self.__get_asset(mac)
        
        if not _type or not mac or not asset: return
                
        asset.update({
                'tags': ['modbus-master'] if _type == 'req' else ['modbus-slave']
        })
        
        
    def parse_cip(self,data):
        name = data.get('name',{}).get('cip')
        vendor = data.get('vendor',{}).get('cip')
        device_type = data.get('device_type',{}).get('cip')
        
        mac = data.get('src', {}).get('eth')
        asset = self.__get_asset(mac)
        
        if not mac or not asset: return
            
        asset.update({
            'name': name,
            'vendor': vendor,
            'type': device_type,
        })
            
        
    def update_assets(self):
        for asset in self.assets:
            if asset.mac == broadcast_mac:
                asset.update({'type':AssetType.Broadcast})
                
                
            if 'modbus-master' in asset.tags and 'modbus-slave' in asset.tags:
                asset.update({'type':AssetType.Mtu})
            elif 'modbus-master' in asset.tags:
                asset.update({'type':AssetType.Hmi})
            elif 'modbus-slave' in asset.tags:
                asset.update({'type':AssetType.Plc})
                
            if 'mbap' in asset.tags:
                asset.update({'type': AssetType.Plc, 'tags':'modbus-slave'})
                
            if 'iso-tsap' in asset.tags:
                asset.update({'type': AssetType.Plc, 'tags':''})
                
            if 'domain' in asset.tags and asset.type == AssetType.Unknown:
                asset.update({'type': AssetType.Router})
                
            if ('http' in asset.tags or 'https' in asset.tags or 'ftp' in asset.tags or 'smtp' in asset.tags)  and asset.type == AssetType.Unknown:
                asset.update({'type': AssetType.Server})
                
                
            if asset.type == AssetType.Unknown and not asset.unknown:
                asset.update({'type':AssetType.Workstation})
    
    def aggregate(self, packet):
        if 'modbus' in packet:
            data = self.modbus_chain.handle(packet)
            self.parse_modbus(data)
        if 'cip' in packet:
            data = self.cip_chain.handle(packet)
            self.parse_cip(data)
        if 'bacnet' in packet:
            data = self.bacnet_chain.handle(packet)
            # self.parse_cip(data)
