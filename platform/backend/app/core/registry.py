from app.core.contracts import Collector


class CollectorRegistry:
    def __init__(self) -> None:
        self._collectors: dict[str, Collector] = {}

    def register(self, collector: Collector) -> None:
        if collector.name in self._collectors:
            raise ValueError(f"Collector already registered: {collector.name}")
        self._collectors[collector.name] = collector

    def get(self, name: str) -> Collector:
        return self._collectors[name]

    def list(self) -> list[dict[str, str]]:
        return [
            {
                "name": item.name,
                "version": item.version,
                "description": item.description,
                "status": "enabled",
            }
            for item in self._collectors.values()
        ]
