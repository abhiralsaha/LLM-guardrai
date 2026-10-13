from abc import ABC, abstractmethod


class LLMClient(ABC):
    @abstractmethod
    def generate(self, system: str, prompt: str) -> str:
        ...
