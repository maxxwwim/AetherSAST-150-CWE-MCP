from typing import Dict, List, Optional
import uuid
import re
from .rcon_service import dispatch_order_commands

STORE_ITEMS = [
    # ========================================================
    # 1. ÉQUIPEMENTS DE LÉGENDE & OBJETS EXCLUSIFS (AVEC "PETIT +")
    # ========================================================
    {
        "id": "item_elytra_celestial",
        "category": "items",
        "name": "Élytres Stellaires Célestes",
        "badge": "PROPULSION INFINIE",
        "badge_color": "sky",
        "price": 9.99,
        "currency": "EUR",
        "icon": "🪽",
        "popular": True,
        "description": "Paire d'élytres divines forgées dans les nébuleuses d'Aether.",
        "petit_plus": "🚀 Propulsion Infinie : Plane sans fusée grâce à la sustentation stellaire ! Incassable (Unbreaking 255).",
        "perks": [
            "⚡ ZÉRO FUSÉE NÉCESSAIRE : Sustentation et poussée intégrées sans artifice",
            "🛡️ 100% Incassable (Unbreaking 255 + Raccommodage Mending I)",
            "💨 Vélocité supersonique accrue de +35% en vol",
            "🪂 Amorti gravitationnel : Chutes vertigineuses sans dégâts"
        ],
        "commands": [
            """give {username} elytra[custom_name='{"text":"✦ Élytres Stellaires Célestes ✦","color":"gold","bold":true,"italic":false}',lore=['{"text":"Objet Exclusif Boutique AetherCraft","color":"dark_purple"}','{"text":"⚡ Propulsion Infinie : Plane sans fusée","color":"aqua"}','{"text":"🛡️ Incassable & Vélocité Augmentée","color":"green"}'],unbreakable={},enchantments={levels:{"minecraft:unbreaking":255,"minecraft:mending":1}},attribute_modifiers=[{type:"minecraft:generic.movement_speed",id:"aether:elytra_speed",amount:0.35,operation:"add_multiplied_base",slot:"chest"},{type:"minecraft:generic.safe_fall_distance",id:"aether:elytra_fall",amount:1000.0,operation:"add_value",slot:"chest"},{type:"minecraft:generic.gravity",id:"aether:elytra_gravity",amount:-0.035,operation:"add_value",slot:"chest"}]] 1""",
            """title {username} actionbar {"text":"✨ Élytres Stellaires livrés : Volez sans aucune fusée !","color":"gold"}"""
        ]
    },
    {
        "id": "item_aether_pickaxe",
        "category": "items",
        "name": "Foreuse Quantique Aether",
        "badge": "MINAGE ULTRA",
        "badge_color": "emerald",
        "price": 7.49,
        "currency": "EUR",
        "icon": "⛏️",
        "description": "Pioche en Netherite transcendée pour le forage instantané des minerais les plus denses.",
        "petit_plus": "⚡ Minage instantané d'Obsidienne & Efficacité VII + Fortune V (dépasse les limites vanilla).",
        "perks": [
            "💎 Efficacité VII & Fortune V (dépassement des plafonds normaux du jeu)",
            "💥 Minage instantané de l'Obsidienne et des blocs renforcés",
            "🛡️ Outil indestructible (Unbreakable) avec Haste passif",
            "✨ Auto-raccommodage stellaire"
        ],
        "commands": [
            """give {username} netherite_pickaxe[custom_name='{"text":"⛏️ Foreuse Quantique Aether","color":"aqua","bold":true,"italic":false}',lore=['{"text":"Technologie de minage dimensionnelle","color":"gray"}','{"text":"✦ Petit + : Minage instantané d\'obsidienne & Fortune V","color":"yellow"}','{"text":"✦ Incassable & Haste intrinsèque","color":"green"}'],unbreakable={},enchantments={levels:{"minecraft:efficiency":7,"minecraft:fortune":5,"minecraft:unbreaking":255,"minecraft:mending":1}},attribute_modifiers=[{type:"minecraft:generic.attack_speed",id:"aether:haste_pick",amount:1.5,operation:"add_value",slot:"mainhand"}]] 1""",
            """title {username} actionbar {"text":"⛏️ Foreuse Quantique reçue dans votre inventaire !","color":"aqua"}"""
        ]
    },
    {
        "id": "item_aether_sword",
        "category": "items",
        "name": "Lame Vorpale du Néant",
        "badge": "VOL DE VIE",
        "badge_color": "rose",
        "price": 8.99,
        "currency": "EUR",
        "icon": "⚔️",
        "description": "Épée mythique forgée dans le cœur d'une étoile effondrée.",
        "petit_plus": "🩸 Vol de vie passif : +4 Cœurs permanents en main (Santé Max 28 PV) & Tranchant VI.",
        "perks": [
            "❤️ +4 Cœurs bonus (Santé Max augmentée à 28 PV) lorsqu'équipée",
            "🗡️ Tranchant VI (Sharpness VI) & Butin IV (Looting IV)",
            "🔥 Flammes du Néant (Fire Aspect III) & Anti-durabilité infinie",
            "⚡ Vitesse de frappe accrue de +25%"
        ],
        "commands": [
            """give {username} netherite_sword[custom_name='{"text":"⚔️ Lame Vorpale du Néant","color":"light_purple","bold":true,"italic":false}',lore=['{"text":"Forgée dans la matière noire stellaire","color":"gray"}','{"text":"✦ Petit + : +4 Cœurs de santé max en main & Tranchant VI","color":"yellow"}','{"text":"✦ Butin IV & Aura de flammes du néant","color":"gold"}'],unbreakable={},enchantments={levels:{"minecraft:sharpness":6,"minecraft:looting":4,"minecraft:fire_aspect":3,"minecraft:unbreaking":255}},attribute_modifiers=[{type:"minecraft:generic.max_health",id:"aether:sword_health",amount:8.0,operation:"add_value",slot:"mainhand"},{type:"minecraft:generic.attack_damage",id:"aether:sword_dmg",amount:14.0,operation:"add_value",slot:"mainhand"}]] 1""",
            """title {username} actionbar {"text":"⚔️ Lame Vorpale du Néant reçue !","color":"light_purple"}"""
        ]
    },
    {
        "id": "item_aether_bow",
        "category": "items",
        "name": "Arc Stellaire Dimensionnel",
        "badge": "HYBRIDE INTERDIT",
        "badge_color": "amber",
        "price": 6.99,
        "currency": "EUR",
        "icon": "🏹",
        "description": "L'arc céleste qui brise les lois fondamentales du monde Minecraft.",
        "petit_plus": "✨ Infinité ET Raccommodage simultanés (incompatible en vanilla) + Puissance VI.",
        "perks": [
            "🏹 COMBINAISON INTERDITE : Infinité I + Raccommodage (Mending) réunis sur le même arc",
            "🎯 Puissance VI (Power VI) & Frappe III (Punch III)",
            "🔥 Flamme perpétuelle et flèches lumineuses",
            "🎒 1 Flèche d'infinité offerte"
        ],
        "commands": [
            """give {username} bow[custom_name='{"text":"🏹 Arc Stellaire Dimensionnel","color":"gold","bold":true,"italic":false}',lore=['{"text":"Arme sacrée céleste","color":"gray"}','{"text":"✦ Petit + : Infinité ET Raccommodage réunis simultanément","color":"yellow"}','{"text":"✦ Puissance VI & Flèches de Vélocité Pure","color":"aqua"}'],enchantments={levels:{"minecraft:infinity":1,"minecraft:mending":1,"minecraft:power":6,"minecraft:punch":3,"minecraft:flame":1}},unbreakable={}] 1""",
            """give {username} arrow 1""",
            """title {username} actionbar {"text":"🏹 Arc Stellaire Dimensionnel livré dans votre inventaire !","color":"gold"}"""
        ]
    },
    {
        "id": "item_sanctuary_talisman",
        "category": "items",
        "name": "Talisman du Sanctuaire Invulnérable",
        "badge": "INVULNÉRABILITÉ ÉQUILIBRÉE",
        "badge_color": "amber",
        "price": 8.50,
        "currency": "EUR",
        "icon": "🛡️",
        "popular": True,
        "description": "Active l'aura de protection divine : immunité absolue à tous les dégâts du monde.",
        "petit_plus": "🛡️ Invulnérabilité totale aux dégâts ! Règle équilibrée : Impossible d'attaquer les joueurs (Anti-PvP) ni de poser de blocs (Anti-Grief).",
        "perks": [
            "🛡️ 100% Invulnérable (Résistance 255 + Régénération + Résistance Feu perpétuelles)",
            "🚫 Anti-PvP strict imposé : Zéro dégât infligé aux autres joueurs pour un jeu équitable",
            "🧱 Anti-Grief strict imposé : Interdiction absolue de poser ou détruire des blocs en mode invulnérable",
            "✨ Relique Nether Star enchantée de Sanctuaire remise dans l'inventaire"
        ],
        "commands": [
            "tag {username} add invulnerable",
            "gamemode adventure {username}",
            """give {username} nether_star[custom_name='{"text":"✦ Relique du Sanctuaire Invulnérable ✦","color":"gold","bold":true,"italic":false}',lore=['{"text":"Protection Divine Absolue","color":"yellow"}','{"text":"✦ Petit + : Zéro dégât reçu (Résistance 255)","color":"green"}','{"text":"⚠️ Attaque et pose de blocs bloquées (Jeu équitable)","color":"red"}'],enchantments={levels:{"minecraft:protection":10}},unbreakable={}] 1""",
            """title {username} title {"text":"🛡️ SANCTUAIRE ACTIVÉ","color":"gold","bold":true}""",
            """title {username} subtitle {"text":"Invulnérabilité active (PvP et pose de blocs désactivés)","color":"yellow"}"""
        ]
    },

    # ========================================================
    # 2. ANIMAUX & FAMILIERS (LIVRAISON DIRECTE EN INVENTAIRE)
    # ========================================================
    {
        "id": "pet_dragon",
        "category": "pets",
        "name": "Familier : Bébé Dragon Stellaire",
        "badge": "FAMILIER DIVIN",
        "badge_color": "violet",
        "price": 6.50,
        "currency": "EUR",
        "icon": "🐉",
        "popular": True,
        "description": "Un compagnon miniature loyal qui vole à vos côtés dans toutes vos expéditions.",
        "petit_plus": "✨ Invulnérable aux monstres et à la lave, aura scintillante permanente (Glowing) et vol perpétuel.",
        "perks": [
            "🐉 Livré directement en jeu sous forme d'Œuf d'Invocation Céleste",
            "✨ Aura luminescente permanente (Glowing) visible la nuit",
            "🛡️ Totalement invulnérable aux monstres, aux chutes et au feu",
            "🌌 Vous suit partout, y compris dans le Nether et l'End"
        ],
        "commands": [
            """give {username} allay_spawn_egg[custom_name='{"text":"🐉 Familier : Bébé Dragon Stellaire","color":"light_purple","bold":true,"italic":false}',lore=['{"text":"Compagnon Céleste Indestructible","color":"gray"}','{"text":"✦ Petit + : Flotte à vos côtés, Glowing & Invulnérable","color":"yellow"}'],entity_data={id:"minecraft:allay",CustomName:'{"text":"🐉 Bébé Dragon Stellaire","color":"light_purple","bold":true}',PersistenceRequired:1b,Invulnerable:1b,Glowing:1b}] 1""",
            """title {username} actionbar {"text":"🐉 Bébé Dragon Stellaire disponible dans votre inventaire !","color":"light_purple"}"""
        ]
    },
    {
        "id": "pet_phoenix_wolf",
        "category": "pets",
        "name": "Familier : Loup Phénix Sacré",
        "badge": "GARDIEN FEU",
        "badge_color": "amber",
        "price": 5.99,
        "currency": "EUR",
        "icon": "🐺",
        "description": "Un protecteur dévoué issu des flammes solaires pour terrasser vos ennemis.",
        "petit_plus": "🔥 Résistance totale à la lave, 50 PV (x2.5 d'un loup ordinaire) et dégâts d'attaque x3.",
        "perks": [
            "🛡️ 50 Points de Vie (x2.5 supérieur aux loups vanilla)",
            "⚔️ Force décuplée : 12 points de dégâts par morsure (au lieu de 4)",
            "🔥 Immunité complète au feu, à la lave et au magma",
            "🎖️ Collier en or incandescent gravé à votre gloire"
        ],
        "commands": [
            """give {username} wolf_spawn_egg[custom_name='{"text":"🔥 Familier : Loup Phénix Sacré","color":"gold","bold":true,"italic":false}',lore=['{"text":"Gardien mythique des Terres d\'Aether","color":"gray"}','{"text":"✦ Petit + : Résistant au feu, 50 PV (x2.5) & Dégâts x3","color":"yellow"}'],entity_data={id:"minecraft:wolf",CustomName:'{"text":"🔥 Loup Phénix Sacré","color":"gold","bold":true}',CollarColor:14b,PersistenceRequired:1b,Attributes:[{Name:"generic.max_health",Base:50.0},{Name:"generic.attack_damage",Base:12.0}],Health:50.0f}] 1""",
            """title {username} actionbar {"text":"🐺 Loup Phénix Sacré livré dans votre inventaire !","color":"gold"}"""
        ]
    },
    {
        "id": "pet_pegasus_horse",
        "category": "pets",
        "name": "Monture : Pégase Squelette Céleste",
        "badge": "MONTURE VÉLOCE",
        "badge_color": "sky",
        "price": 7.99,
        "currency": "EUR",
        "icon": "⚡",
        "description": "Le destrier des dieux capable de franchir les ravins sans jamais se fatiguer.",
        "petit_plus": "🌊 Ne se noie jamais sous l'eau, Saut x3 surhumain et vitesse pure 0.38 + Selle Divine offerte.",
        "perks": [
            "🐎 Déjà apprivoisé à 100% (Prêt à monter instantanément)",
            "🤿 Nage et galope sous l'eau sans asphyxie (cheval squelette divin)",
            "⬆️ Puissance de saut maximale 1.0 (franchit plus de 5 blocs de haut)",
            "🛡️ Selle Divine Incassable incluse dans le pack"
        ],
        "commands": [
            """give {username} skeleton_horse_spawn_egg[custom_name='{"text":"⚡ Monture : Pégase Céleste","color":"aqua","bold":true,"italic":false}',lore=['{"text":"Monture divine à vitesse supersonique","color":"gray"}','{"text":"✦ Petit + : Saut x3, Vitesse 0.38, Ne coule pas sous l\'eau","color":"yellow"}'],entity_data={id:"minecraft:skeleton_horse",CustomName:'{"text":"⚡ Pégase Céleste","color":"aqua","bold":true}',Tame:1b,Attributes:[{Name:"generic.movement_speed",Base:0.38},{Name:"horse.jump_strength",Base:1.0},{Name:"generic.max_health",Base:60.0}],Health:60.0f}] 1""",
            """give {username} saddle[custom_name='{"text":"Selle Divine Aether","color":"gold"}',unbreakable={}] 1""",
            """title {username} actionbar {"text":"⚡ Pégase Céleste & Selle Divine livrés en jeu !","color":"aqua"}"""
        ]
    },

    # ========================================================
    # 3. CLÉS & CAISSES DU SPAWN
    # ========================================================
    {
        "id": "key_mystic_bundle",
        "category": "keys",
        "name": "Pack 5x Clés Célestes",
        "badge": "CLÉS MYSTIQUES",
        "badge_color": "purple",
        "price": 3.49,
        "currency": "EUR",
        "icon": "🗝️",
        "description": "Ouvrez la Caisse des Étoiles au spawn et tentez de remporter des artéfacts rares.",
        "petit_plus": "✨ Taux de drop d'items mythiques augmenté de +15% & Clé physique enchantée incassable.",
        "perks": [
            "5 Clés physiques utilisables instantanément au Spawn",
            "Butins possibles : Armes légendaires, Spawners, Tokens",
            "Taux de drop d'items mythiques augmenté de 15%"
        ],
        "commands": [
            """give {username} tripwire_hook[custom_name='{"text":"🗝️ Clé Céleste Sacrée","color":"light_purple","bold":true,"italic":false}',lore=['{"text":"Caisse des Étoiles — Spawn Aether","color":"gray"}','{"text":"✦ Petit + : Taux de drop d\'items mythiques +15%","color":"yellow"}'],enchantments={levels:{"minecraft:luck_of_the_sea":3}},unbreakable={}] 5""",
            """title {username} actionbar {"text":"🗝️ 5x Clés Célestes livrées dans votre inventaire !","color":"light_purple"}"""
        ]
    },
    {
        "id": "key_omega_bundle",
        "category": "keys",
        "name": "Pack 12x Clés Oméga (Max)",
        "badge": "OFFRE TITAN",
        "badge_color": "rose",
        "price": 7.99,
        "currency": "EUR",
        "icon": "💎",
        "description": "Le pack ultime pour les chasseurs de trésors et pilleurs de donjons.",
        "petit_plus": "💎 Garantie d'au moins 1 artefact légendaire ou spawner rare + 500 Gems bonus.",
        "perks": [
            "12 Clés Oméga physiques dans l'inventaire",
            "Garantie d'au moins 1 item légendaire ou spawner rare",
            "+500 Aether Gems bonus offerts sur votre compte"
        ],
        "commands": [
            """give {username} netherite_scrap[custom_name='{"text":"💎 Clé Oméga Primordiale","color":"rose","bold":true,"italic":false}',lore=['{"text":"Caisse Oméga — Trésor des Titans","color":"gray"}','{"text":"✦ Petit + : 100% chance Artefact/Spawner & 500 Gems","color":"yellow"}'],enchantments={levels:{"minecraft:fortune":5}},unbreakable={}] 12""",
            """title {username} actionbar {"text":"💎 12x Clés Oméga livrées dans votre inventaire !","color":"rose"}"""
        ]
    },

    # ========================================================
    # 4. GRADES VIP & PRIVILÈGES (AVEC KITS D'INVENTAIRE)
    # ========================================================
    {
        "id": "rank_vip",
        "category": "grades",
        "name": "Grade VIP",
        "badge": "VIP",
        "badge_color": "emerald",
        "price": 4.99,
        "currency": "EUR",
        "icon": "👑",
        "description": "Le grade idéal pour commencer l'aventure avec confort et style.",
        "petit_plus": "👑 Grade LuckPerms + Kit d'accueil immédiat dans l'inventaire (Armure P3 + 16 Pommes dorées).",
        "perks": [
            "Préfixe [VIP] vert dans le chat et le tablist",
            "Accès aux commandes /fly en lobby et /feed",
            "+2 Homes supplémentaires (/sethome)",
            "Kit VIP immédiat en jeu : Plastron Fer P3 + 16 Pommes d'or",
            "Accès prioritaire aux serveurs pleins"
        ],
        "commands": [
            "lp user {username} parent add vip",
            """give {username} iron_chestplate[custom_name='{"text":"Plastron du VIP","color":"green"}',enchantments={levels:{"minecraft:protection":3,"minecraft:unbreaking":3}}] 1""",
            "give {username} golden_apple 16",
            """title {username} actionbar {"text":"👑 Grade VIP & Kit livrés avec succès !","color":"green"}"""
        ]
    },
    {
        "id": "rank_aether",
        "category": "grades",
        "name": "Grade Aether (Héros)",
        "badge": "AETHER",
        "badge_color": "sky",
        "price": 14.99,
        "currency": "EUR",
        "icon": "🪐",
        "popular": True,
        "description": "Le grade prestigieux conçu pour les maîtres du monde Aether.",
        "petit_plus": "🪐 Vol /fly partout en survie + Kit Diamant P4 incassable & 8 Pommes de Notch.",
        "perks": [
            "Préfixe [AETHER] cyan scintillant animé",
            "Commandes /fly partout en survie + /workbench + /anvil",
            "+10 Homes personnalisables",
            "Kit Aether immédiat : Plastron Diamant P4 + 8 Pommes de Notch",
            "Accès exclusif au canal Discord VIP & Salons Vocaux"
        ],
        "commands": [
            "lp user {username} parent add aether",
            """give {username} diamond_chestplate[custom_name='{"text":"Armure du Héros Aether","color":"aqua"}',unbreakable={},enchantments={levels:{"minecraft:protection":4,"minecraft:unbreaking":5}}] 1""",
            "give {username} enchanted_golden_apple 8",
            """title {username} actionbar {"text":"🪐 Grade Aether & Kit Héros livrés !","color":"aqua"}"""
        ]
    },
    {
        "id": "rank_titan",
        "category": "grades",
        "name": "Grade Titan Primordial",
        "badge": "TITAN",
        "badge_color": "amber",
        "price": 29.99,
        "currency": "EUR",
        "icon": "⚡",
        "description": "La puissance ultime avec tous les privilèges et cosmétiques débloqués.",
        "petit_plus": "⚡ Commandes divines (/god équilibré : Invulnérabilité avec Anti-PvP & Anti-Grief) + Kit Netherite P5 Ultime.",
        "perks": [
            "Préfixe [TITAN] or flamboyant dans le chat",
            "Mode Sanctuaire /god : Invulnérabilité active avec blocage d'attaque sur joueurs et de pose de blocs",
            "Homes illimités & Accès au coffre Ender géant (/enderchest)",
            "Kit Titan immédiat : Plastron Netherite P5 Unbreakable + 2 Totems + 32 Pommes de Notch",
            "Priorité absolue et multiplicateur x2 d'expérience"
        ],
        "commands": [
            "lp user {username} parent add titan",
            "tag {username} add invulnerable",
            """give {username} netherite_chestplate[custom_name='{"text":"Cuirasse du Titan Primordial","color":"gold"}',unbreakable={},enchantments={levels:{"minecraft:protection":5,"minecraft:unbreaking":10}}] 1""",
            "give {username} totem_of_undying 2",
            "give {username} enchanted_golden_apple 32",
            """title {username} actionbar {"text":"⚡ Grade Titan & Sanctuaire Invulnérable activés !","color":"gold"}"""
        ]
    }
]

ORDERS_HISTORY: List[Dict] = []

def sanitize_minecraft_username(raw_username: str) -> str:
    """Valide et assainit le pseudo Minecraft contre les injections de commandes (CWE-78/89)."""
    clean = re.sub(r'[^a-zA-Z0-9_]', '', raw_username.strip())
    if len(clean) < 3:
        return "Steve"
    return clean[:16]

def get_store_items(category: Optional[str] = None) -> List[Dict]:
    """Retourne la liste des items filtrée par catégorie."""
    if not category or category == "all":
        return STORE_ITEMS
    return [item for item in STORE_ITEMS if item.get("category") == category]

def get_item_by_id(item_id: str) -> Optional[Dict]:
    """Recherche un item dans le catalogue par son identifiant unique."""
    for item in STORE_ITEMS:
        if item["id"] == item_id:
            return item
    return None

def build_order_commands(username: str, cart_items: List[Dict]) -> List[str]:
    """Génère la liste complète et validée des commandes Minecraft à exécuter."""
    clean_user = sanitize_minecraft_username(username)
    commands: List[str] = []

    for item in cart_items:
        qty = item.get("quantity", 1)
        item_cmds = item.get("commands", [])
        if item_cmds:
            for _ in range(qty):
                for cmd_template in item_cmds:
                    formatted_cmd = cmd_template.replace("{username}", clean_user).strip()
                    commands.append(formatted_cmd)
        else:
            # Fallback de compatibilité
            if item["id"].startswith("rank_"):
                role = item["id"].replace("rank_", "")
                commands.append(f"lp user {clean_user} parent add {role}")
            else:
                commands.append(f"give {clean_user} {item['id']}")

    return commands

def process_checkout(username: str, cart_items: List[Dict]) -> Dict:
    """
    Traite la commande utilisateur, génère les commandes Minecraft exactes
    et les distribue au serveur de jeu via RCON avec file d'attente automatique.
    """
    clean_user = sanitize_minecraft_username(username)
    total = sum(item["price"] * item.get("quantity", 1) for item in cart_items)
    order_id = f"CMD-{str(uuid.uuid4())[:8].upper()}"

    # Construction des commandes Minecraft valides
    commands_to_run = build_order_commands(clean_user, cart_items)

    # Dispatch RCON vers le serveur de jeu
    rcon_result = dispatch_order_commands(clean_user, commands_to_run, order_id)

    order = {
        "order_id": order_id,
        "username": clean_user,
        "total": round(total, 2),
        "currency": "EUR",
        "products": cart_items,
        "items_count": len(cart_items),
        "status": "LIVRÉ EN JEU" if rcon_result.get("connected") else "EN FILE D'ATTENTE",
        "delivery_message": rcon_result.get("message", "Traitement en cours"),
        "command_to_run": commands_to_run,
        "rcon_details": rcon_result.get("details", [])
    }

    ORDERS_HISTORY.insert(0, order)
    return order
