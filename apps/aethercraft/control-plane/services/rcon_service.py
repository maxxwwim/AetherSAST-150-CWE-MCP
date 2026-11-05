import socket
import struct
import json
import os
import threading
from typing import List, Dict, Tuple, Optional

RCON_HOST = os.environ.get("AETHER_RCON_HOST", "127.0.0.1")
RCON_PORT = int(os.environ.get("AETHER_RCON_PORT", 25575))
RCON_PASSWORD = os.environ.get("AETHER_RCON_PASSWORD", "aether2026")

PENDING_QUEUE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".aether_pending_deliveries.json")
_QUEUE_LOCK = threading.Lock()

SERVERDATA_AUTH = 3
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_RESPONSE_VALUE = 0

class RconClient:
    """
    Client RCON pur Python conforme au protocole officiel Minecraft / Valve.
    Gère l'authentification et l'exécution sécurisée sans dépendance externe.
    """
    def __init__(self, host: str = RCON_HOST, port: int = RCON_PORT, password: str = RCON_PASSWORD, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def _read_packet(self) -> Tuple[int, int, str]:
        if not self.sock:
            raise ConnectionError("Socket RCON non connectée")
        
        len_data = self.sock.recv(4)
        if len(len_data) < 4:
            raise ConnectionError("Réponse RCON tronquée")
        length = struct.unpack("<i", len_data)[0]

        data = b""
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk

        req_id, p_type = struct.unpack("<ii", data[0:8])
        body = data[8:-2].decode("utf-8", errors="replace")
        return req_id, p_type, body

    def _send_packet(self, req_id: int, p_type: int, payload: str):
        if not self.sock:
            raise ConnectionError("Socket RCON non connectée")
        payload_bytes = payload.encode("utf-8")
        # Packet: Length (int32) + ReqID (int32) + Type (int32) + Payload + \x00\x00
        length = 4 + 4 + len(payload_bytes) + 2
        packet = struct.pack("<iii", length, req_id, p_type) + payload_bytes + b"\x00\x00"
        self.sock.sendall(packet)

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

            # Authentification
            self._send_packet(1, SERVERDATA_AUTH, self.password)
            req_id, p_type, _ = self._read_packet()

            # Parfois un paquet vide intermédiaire arrive avant la réponse d'auth
            if p_type == SERVERDATA_RESPONSE_VALUE:
                req_id, p_type, _ = self._read_packet()

            if req_id == -1:
                self.close()
                return False
            return True
        except Exception:
            self.close()
            return False

    def command(self, cmd: str) -> Tuple[bool, str]:
        if not self.sock:
            if not self.connect():
                return False, "Serveur Minecraft injoignable via RCON"
        try:
            # Enlever le slash initial si présent
            clean_cmd = cmd.lstrip("/")
            self._send_packet(2, SERVERDATA_EXECCOMMAND, clean_cmd)
            _, _, response = self._read_packet()
            return True, response
        except Exception as e:
            self.close()
            return False, str(e)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

def load_pending_deliveries() -> List[Dict]:
    with _QUEUE_LOCK:
        if not os.path.exists(PENDING_QUEUE_FILE):
            return []
        try:
            with open(PENDING_QUEUE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

def save_pending_deliveries(queue: List[Dict]):
    with _QUEUE_LOCK:
        try:
            with open(PENDING_QUEUE_FILE, "w", encoding="utf-8") as f:
                json.dump(queue, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[WARN] Impossible de sauvegarder la file d'attente RCON: {e}")

def enqueue_delivery(username: str, commands: List[str], order_id: str):
    queue = load_pending_deliveries()
    queue.append({
        "order_id": order_id,
        "username": username,
        "commands": commands
    })
    save_pending_deliveries(queue)

def dispatch_order_commands(username: str, commands: List[str], order_id: str) -> Dict:
    """
    Tente la livraison directe via RCON au serveur Minecraft.
    Si le serveur n'est pas actif ou joignable, les commandes sont placées
    en file d'attente persistante pour livraison automatique dès qu'il démarre.
    """
    client = RconClient()
    connected = client.connect()
    results = []

    if connected:
        for cmd in commands:
            success, resp = client.command(cmd)
            results.append({
                "command": cmd,
                "success": success,
                "response": resp
            })
        client.close()
        # Message de broadcast ou action bar
        return {
            "status": "DELIVERED_INSTANT",
            "connected": True,
            "message": "Livré instantanément en jeu dans l'inventaire !",
            "details": results
        }
    else:
        # File d'attente
        enqueue_delivery(username, commands, order_id)
        return {
            "status": "QUEUED_PENDING_SERVER",
            "connected": False,
            "message": "Placé en file d'attente sécurisée (sera injecté dès le lancement du serveur)",
            "details": [{"command": c, "success": True, "queued": True} for c in commands]
        }

def flush_pending_queue() -> int:
    """
    Tente de vider les commandes en attente lorsque le serveur redevient actif.
    """
    queue = load_pending_deliveries()
    if not queue:
        return 0

    client = RconClient()
    if not client.connect():
        return 0

    remaining = []
    delivered = 0
    for order in queue:
        order_success = True
        for cmd in order["commands"]:
            ok, _ = client.command(cmd)
            if not ok:
                order_success = False
                break
        if order_success:
            delivered += 1
        else:
            remaining.append(order)

    client.close()
    save_pending_deliveries(remaining)
    return delivered
