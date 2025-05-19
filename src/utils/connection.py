from .assets import Asset

class Connection:
    def __init__(self, src:Asset=None, dst:Asset=None, ttl=-1, tags = [], data_flows = []):
        self.src = src
        self.dst = dst
        self.ttl = ttl
        self.tags = tags
        self.data_flows = data_flows
    
    
    def add_data_flow(self,instance):
        self.data_flows.append(instance)
           
    def __str__(self):
        return f'[Connection] {self.src.get_identifier()}(Type: {self.src.type}) <-> {self.dst.get_identifier()}(Type: {self.src.type})'