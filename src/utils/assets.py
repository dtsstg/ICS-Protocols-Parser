from .constants import AssetType

class Asset:
    def __init__(self, mac=None, ips=set(), tags=[], asset_type=AssetType.Unknown, unknown=None, name=None, vendor=None, ports = set()):
        self.mac = mac
        self.ports = ports
        self.ips = ips
        self.tags = tags
        self.type = asset_type
        self.unknown =unknown
        self.name=name
        self.vendor=vendor
            
    def get_identifier(self):
        return self.unknown if self.unknown else self.mac
    
    def add_ip(self,instance):
        self.ips.add(instance)    
    
    def update(self,payload):
        # print('Update asset before',self)
        mac = payload.get('mac', self.mac)
        ips = payload.get('ips', set())
        asset_type = payload.get('type', self.type)
        tags = payload.get('tags', [])
        name = payload.get('name', self.name)
        vendor = payload.get('vendor', self.vendor)
        ports = payload.get('ports', set())
        
        
        if name: self.name = name
        if vendor: self.vendor = vendor
        
        if mac: self.mac=mac
        
        if ips:
            if type(ips) is set: 
                self.ips=self.ips.union(ips)
            else:
                self.ips.add(ips)
                
        if tags: 
            if type(tags) is list: 
                self.tags=list(set(self.tags + tags))
            else:
                self.tags.append(tags)
            
        if asset_type: self.type = asset_type
        if ports: 
            if type(self.ports) is set:
                self.ports = self.ports.union(ports) 
            else:
                self.ports.add(self.ports)
        # print('Update asset',self)
       
        
    def __hash__(self):
        return hash(self.get_identifier())
    
    def __eq__(self, other):
        if not isinstance(other, Asset):
            return False
        return self.unknown == other.unknown or self.mac == other.mac
    
    def __str__(self):
        return '[Asset] /Not identified/ (id={})'.format(self.unknown) if self.unknown else '[Asset] Mac:{mac} Ip: {ip} Tags:{tags} Type:{type}'.format(mac=self.mac,ip=self.ips,tags=','.join(self.tags) if self.tags else '/no tags/',type=self.type)