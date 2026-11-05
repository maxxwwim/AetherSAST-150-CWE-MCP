from typing import List, Dict

MINERAL_PRICES = [
    {
        "id": "netherite",
        "name": "Lingot de Netherite Céleste",
        "symbol": "NETH",
        "icon": "🪙",
        "category": "Légendaire",
        "base_price": 4500.0,
        "sell_price": 4275.0,
        "trend": "+5.4%",
        "is_up": True,
        "volume_24h": "1,420 u",
        "unit": "Aether Coins / u"
    },
    {
        "id": "diamond",
        "name": "Diamant Astral Pur",
        "symbol": "DIAM",
        "icon": "💎",
        "category": "Rare",
        "base_price": 850.0,
        "sell_price": 807.5,
        "trend": "-1.2%",
        "is_up": False,
        "volume_24h": "14,850 u",
        "unit": "Aether Coins / u"
    },
    {
        "id": "emerald",
        "name": "Émeraude Marchande Royale",
        "symbol": "EMER",
        "icon": "🟢",
        "category": "Économie",
        "base_price": 420.0,
        "sell_price": 399.0,
        "trend": "+2.8%",
        "is_up": True,
        "volume_24h": "32,100 u",
        "unit": "Aether Coins / u"
    },
    {
        "id": "gold",
        "name": "Lingot d'Or Solaire",
        "symbol": "GOLD",
        "icon": "🌟",
        "category": "Métal Sacré",
        "base_price": 195.0,
        "sell_price": 185.0,
        "trend": "+0.9%",
        "is_up": True,
        "volume_24h": "48,200 u",
        "unit": "Aether Coins / u"
    },
    {
        "id": "amethyst",
        "name": "Éclat d'Améthyste Résonnante",
        "symbol": "AMETH",
        "icon": "🔮",
        "category": "Magie",
        "base_price": 140.0,
        "sell_price": 133.0,
        "trend": "+14.7%",
        "is_up": True,
        "volume_24h": "8,950 u",
        "unit": "Aether Coins / u"
    },
    {
        "id": "iron",
        "name": "Lingot de Fer Renforcé",
        "symbol": "IRON",
        "icon": "⚙️",
        "category": "Industrie",
        "base_price": 75.0,
        "sell_price": 71.0,
        "trend": "-0.5%",
        "is_up": False,
        "volume_24h": "120,400 u",
        "unit": "Aether Coins / u"
    }
]

def get_market_minerals() -> List[Dict]:
    return MINERAL_PRICES
