from abc import ABC, abstractmethod

from utils import AbstractHandler

class IProtocolParser(ABC):
    def __init__(self, tag:str):
        self.metadata = dict()
        self.tag = tag
        
     
    @abstractmethod
    def aggregate(self, packet )->dict:
        raise NotImplementedError
            
class IProtocolParserChainItem(AbstractHandler, IProtocolParser):
    def __init__(self, tag):
        super().__init__(tag)
        self._first_handler = self
        
    def update_metadata(self,base:dict, data:dict, dict_key=None):
        
        if data == None: return 
        for key,value in data.items():
            if key not in base.keys():
                base[key] = {}
            base[key][dict_key if dict_key else self.tag] = value
        return base
    
    @abstractmethod
    def aggregate(self, packet)->dict:
        raise NotImplementedError
    
    def handle(self, request, d={}):
        metadata = self.aggregate(request)
        
        d = self.update_metadata(d,metadata, self.tag)
        if self._next_handler:
            return self._next_handler.handle(request,d)
        return d



    
    
    
    
    