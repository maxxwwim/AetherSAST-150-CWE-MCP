from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class StoreItem:
    id: str
    category: str
    name: str
    price: float
    currency: str = "EUR"
    icon: str = "📦"
    badge: Optional[str] = None
    badge_color: Optional[str] = None
    popular: bool = False
    description: str = ""
    petit_plus: Optional[str] = None
    perks: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)

@dataclass
class Cart:
    items: List[StoreItem] = field(default_factory=list)

    @property
    def total(self) -> float:
        return sum(item.price for item in self.items)

    @property
    def count(self) -> int:
        return len(self.items)

@dataclass
class OrderTicket:
    order_id: str
    username: str
    items: List[StoreItem]
    total: float
    created_at: str
    status: str = "pending"
