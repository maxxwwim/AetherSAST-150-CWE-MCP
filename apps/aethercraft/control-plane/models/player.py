from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class LeaderboardEntry:
    rank: int
    name: str
    skin_uuid: str
    stat_value: str
    badge: str

@dataclass
class PlayerProfile:
    username: str
    uuid: str
    grade: str
    grade_color: str
    playtime: str
    blocks_mined: int
    kills: int
    deaths: int
    balance: float
    badges: List[str] = field(default_factory=list)
