# ========================================================
# AETHER SANCTUARY - CONTRAT D'INVULNÉRABILITÉ ÉQUILIBRÉ
# Règle : Si Invulnérable -> Protection totale aux dégâts,
# mais interdiction d'attaquer les autres joueurs et de poser des blocs.
# ========================================================

# 1. Protection Intégrale aux Dégâts (Résistance & Régénération)
effect give @a[tag=invulnerable] minecraft:resistance 2 255 true
effect give @a[tag=invulnerable] minecraft:fire_resistance 2 255 true
effect give @a[tag=invulnerable] minecraft:regeneration 2 255 true

# 2. Interdiction d'Attaquer / Frapper les Joueurs (Weakness 255 = 0 dégât infligé)
effect give @a[tag=invulnerable] minecraft:weakness 2 255 true

# 3. Interdiction de Poser et Casser des Blocs (Mode Aventure imposé aux invulnérables)
gamemode adventure @a[tag=invulnerable,gamemode=survival]

# 4. Message d'avertissement permanent dans l'Action Bar
title @a[tag=invulnerable] actionbar {"text":"🛡️ SANCTUAIRE ACTIF : Dégâts annulés | Attaque & Pose de blocs bloquées","color":"gold"}

# 5. Restauration instantanée en Survie dès que l'invulnérabilité est retirée
gamemode survival @a[tag=!invulnerable,gamemode=adventure]
