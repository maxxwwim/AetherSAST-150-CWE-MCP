from dataclasses import dataclass

@dataclass
class MineralItem:
    id: str
    name: str
    symbol: str
    icon: str
    category: str
    base_price: float
    sell_price: float
    trend: str
    is_up: bool
    volume_24h: str
    unit: str = "Aether Coins / u"
