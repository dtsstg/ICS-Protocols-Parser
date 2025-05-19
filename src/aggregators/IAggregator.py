from abc import ABC, abstractmethod

class IAggregator(ABC):
    def __init__(self):
        self.init_chain()
    
    @abstractmethod
    def init_chain(self):
        raise NotImplementedError
    
    @abstractmethod
    def aggregate(self):
        raise NotImplementedError