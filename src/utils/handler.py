from abc import ABC, abstractmethod
from typing import Any, Optional


class Handler(ABC):
    @abstractmethod
    def set_next(self, handler):
        pass

    @abstractmethod
    def handle(self, *args, **kwargs) -> Optional[str]:
        pass


class AbstractHandler(Handler):
    _first_handler: Handler = None
    
    _next_handler: Handler = None

    def final(self):
        return self._first_handler
    
    def set_next(self, handler: Handler) -> Handler:
        handler._first_handler = self._first_handler if self._first_handler else self
        
        self._next_handler = handler
        return handler

    @abstractmethod
    def handle(self, request: Any, *args, **kwargs) -> str:
        if self._next_handler:
            return self._next_handler.handle(request)

        return None