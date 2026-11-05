from typing import Dict, Any, List
from .mc_api import get_paper_build_info, get_purpur_build_info, get_plugin_presets

def generate_aikar_jvm_flags(heap_gb: int) -> List[str]:
    """
    Génère les flags JVM recommandés par Aikar (G1GC tuning) pour serveur Minecraft.
    """
    heap_str = f"{heap_gb}G"
    return [
        f"-Xms{heap_str}",
        f"-Xmx{heap_str}",
        "-XX:+UseG1GC",
        "-XX:+ParallelRefProcEnabled",
        "-XX:MaxGCPauseMillis=200",
        "-XX:+UnlockExperimentalVMOptions",
        "-XX:+DisableExplicitGC",
        "-XX:+AlwaysPreTouch",
        "-XX:G1NewSizePercent=30",
        "-XX:G1MaxNewSizePercent=40",
        "-XX:G1ReservePercent=20",
        "-XX:SurvivorRatio=32",
        "-XX:InitiatingHeapOccupancyPercent=15",
        "-XX:G1MixedGCLiveThresholdPercent=90",
        "-XX:G1RSetUpdatingPauseTimePercent=5",
        "-Dterminal.jline=false",
        "-Dterminal.ansi=true"
    ]

def build_server_manifest(
    server_id: str,
    name: str,
    core_type: str = "paper",
    mc_version: str = "1.21.1",
    ram_gb: int = 4,
    plugins: List[str] = None,
    port: int = 25565,
    motd: str = "§bAetherCraft §7— Serveur Optimisé",
    difficulty: str = "hard"
) -> Dict[str, Any]:
    """
    Génère le dictionnaire complet conforme à la spécification AETHER_MC_MANIFEST_SPEC (v1.0).
    """
    if plugins is None:
        plugins = ["chunky", "spark"]

    # Résolution du core
    if core_type.lower() == "purpur":
        core_info = get_purpur_build_info(mc_version)
    else:
        core_info = get_paper_build_info(mc_version)

    # Résolution des plugins
    plugin_artifacts = get_plugin_presets(plugins)

    # Configuration properties
    server_props = (
        f"server-port={port}\n"
        f"motd={motd}\n"
        f"difficulty={difficulty}\n"
        f"online-mode=true\n"
        f"pvp=true\n"
        f"view-distance=10\n"
        f"simulation-distance=8\n"
        f"max-players=20\n"
        f"enable-command-block=true\n"
        f"enable-rcon=true\n"
        f"rcon.port=25575\n"
        f"rcon.password=aether2026\n"
        f"broadcast-rcon-to-ops=true\n"
    )

    manifest = {
        "$schema": "https://aether.local/schemas/mc-manifest-v1.json",
        "version": "1.0",
        "server_id": server_id,
        "name": name,
        "runtime": {
            "java_major_version": 21,
            "vendor": "adoptium",
            "heap_min": f"{ram_gb}G",
            "heap_max": f"{ram_gb}G",
            "jvm_flags": generate_aikar_jvm_flags(ram_gb)
        },
        "core": {
            "type": core_type,
            "mc_version": mc_version,
            "build": core_info["build"],
            "target_jar": core_info["target_jar"],
            "download_url": core_info["download_url"],
            "sha256": core_info.get("sha256", "")
        },
        "plugins_and_mods": plugin_artifacts,
        "configs": {
            "eula.txt": "eula=true\n",
            "server.properties": server_props,
            "world/datapacks/aether_sanctuary/pack.mcmeta": '{\n  "pack": {\n    "pack_format": 48,\n    "description": "Aether Sanctuary - Regle Invulnerable Equilibre"\n  }\n}\n',
            "world/datapacks/aether_sanctuary/data/minecraft/tags/function/tick.json": '{\n  "values": [\n    "aether:tick"\n  ]\n}\n',
            "world/datapacks/aether_sanctuary/data/aether/function/tick.mcfunction": (
                "# Regle Aether Sanctuary : Si invulnerable -> degats annules, PvP et pose de blocs bloques\n"
                "effect give @a[tag=invulnerable] minecraft:resistance 2 255 true\n"
                "effect give @a[tag=invulnerable] minecraft:fire_resistance 2 255 true\n"
                "effect give @a[tag=invulnerable] minecraft:weakness 2 255 true\n"
                "gamemode adventure @a[tag=invulnerable,gamemode=survival]\n"
                'title @a[tag=invulnerable] actionbar {"text":"🛡️ SANCTUAIRE ACTIF : Dégâts annulés | Attaque & Pose de blocs bloquées","color":"gold"}\n'
                "gamemode survival @a[tag=!invulnerable,gamemode=adventure]\n"
            ),
            "world/datapacks/aether_sanctuary/data/aether/function/enable_god.mcfunction": (
                "tag @s add invulnerable\n"
                "gamemode adventure @s\n"
                'title @s title {"text":"🛡️ SANCTUAIRE ACTIVÉ","color":"gold","bold":true}\n'
            ),
            "world/datapacks/aether_sanctuary/data/aether/function/disable_god.mcfunction": (
                "tag @s remove invulnerable\n"
                "gamemode survival @s\n"
                "effect clear @s minecraft:resistance\n"
                "effect clear @s minecraft:weakness\n"
                'title @s title {"text":"⚔️ SANCTUAIRE DÉSACTIVÉ","color":"red","bold":true}\n'
            )
        }
    }

    return manifest
