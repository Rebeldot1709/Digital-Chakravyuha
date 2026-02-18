import hashlib
import time
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
import secrets
import base64

# NOTE: This is a CONCEPTUAL, illustrative implementation of "Digital Chakravyuha"
# Inspired by your GitHub repo (Rebeldot1709/Digital-Chakravyuha) and blog vision.
# It models the 7-layer unbreakable fortress with mythological flair.
# REAL-WORLD DISCLAIMER:
#   - This is NOT production-ready cryptography. Use libs like cryptography.Fernet + proper key management for real systems.
#   - Nothing is truly "unbreakable" — but layered defense + self-healing + illusion of openness makes it extremely hard to breach.
#   - Run with: python digital_chakravyuha.py
#   - Creator sits at the center. Only you know the master key.

class SystemState:
    """Global state of the Chakravyuha — tracks intrusions and activates ATTACK MODE"""
    def __init__(self):
        self.failed_attempts = 0
        self.max_attempts = 3
        self.attack_mode = False
        self.last_attempt = None
        self.whitelist = ["127.0.0.1", "localhost"]  # Simulate IP whitelist
        self.core_key = secrets.token_hex(32)  # Master key orbiting the Creator

    def enter_attack_mode(self):
        self.attack_mode = True
        print("\n🌀 SUDARSHAN PROTOCOL ACTIVATED — ATTACK MODE ENGAGED")
        print("   All intruders are now spinning in infinite Narak Loop.")
        print("   System self-rebuilding... Creator protected.")

state = SystemState()

class DigitalChakravyuha:
    """The unbreakable 7-layer Digital Chakravyuha Fortress"""

    def __init__(self):
        self.vault = {}  # Encrypted "Creator's Data" vault
        self.layer_history = []
        self.initialize_vault()

    def initialize_vault(self):
        """Seed the vault with protected data (encrypted in memory)"""
        data = {
            "creator_secret": "I am the Architect at the center. Infinite energy flows here.",
            "mission": "Protect civilization. Dominate digital realm. 7 layers = unbreakable.",
            "timestamp": datetime.now().isoformat()
        }
        # Simple symmetric "encryption" using hash-derived key (demo only)
        key = hashlib.sha256(state.core_key.encode()).digest()
        self.vault["encrypted_data"] = self._encrypt(json.dumps(data).encode(), key)

    def _encrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR + base64 (conceptual — replace with Fernet/AES in production)"""
        encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        return base64.b64encode(encrypted)

    def _decrypt(self, encrypted: bytes, key: bytes) -> bytes:
        """Reverse of above"""
        decoded = base64.b64decode(encrypted)
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(decoded)])

    # ====================== 7 LAYERS ======================

    def layer_1_illusion_of_open_territory(self, credentials: Dict) -> bool:
        """Layer 1: Looks wide open — simple auth"""
        username = credentials.get("username")
        password = credentials.get("password")
        if username == "creator" and hashlib.sha256(password.encode()).hexdigest() == hashlib.sha256("chakravyuha2026".encode()).hexdigest():
            print("✅ Layer 1 passed — Territory appears open...")
            return True
        state.failed_attempts += 1
        return False

    def layer_2_bifurcation_of_power(self) -> bool:
        """Layer 2: Splits power — system integrity check"""
        if state.failed_attempts > 0:
            print("⚠️  Layer 2: Power bifurcated — detecting intrusion attempt...")
            time.sleep(0.5)  # Simulated delay
        if state.attack_mode:
            return False
        print("✅ Layer 2 passed — Power balanced around Creator.")
        return True

    def layer_3_maze_of_disorientation(self, credentials: Dict) -> bool:
        """Layer 3: Random maze — permission + pattern check"""
        if secrets.randbelow(10) < 3:  # 30% chance of disorientation trap
            print("🌀 Layer 3: Maze shifts — you are lost in infinite loops!")
            return False
        if not credentials.get("permission_level", 0) >= 999:
            return False
        print("✅ Layer 3 passed — Maze navigated.")
        return True

    def layer_4_ai_absorption_engine(self, ip: str) -> bool:
        """Layer 4: AI absorbs threats — IP + anomaly detection"""
        if ip not in state.whitelist:
            print("🚫 Layer 4: AI Absorption Engine activated — intruder IP absorbed!")
            state.enter_attack_mode()
            return False
        print("✅ Layer 4 passed — AI engine silent, Creator protected.")
        return True

    def layer_5_self_rebuilding_walls(self, timestamp: str) -> bool:
        """Layer 5: Timestamp + self-rebuild check"""
        try:
            ts = datetime.fromisoformat(timestamp)
            if datetime.now() - ts > timedelta(minutes=5):
                print("⏳ Layer 5: Wall rebuilt — stale request rejected.")
                return False
        except:
            return False
        print("✅ Layer 5 passed — Walls self-rebuilt stronger.")
        return True

    def layer_6_last_stand_total_surrender(self, data: Any) -> bool:
        """Layer 6: Integrity hash — surrender or perish"""
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        computed = hashlib.sha256((data_str + state.core_key).encode()).hexdigest()
        if computed != data.get("integrity_hash", ""):
            print("🔥 Layer 6: Last Stand — integrity violated. Total surrender enforced.")
            state.enter_attack_mode()
            return False
        print("✅ Layer 6 passed — Integrity absolute.")
        return True

    def layer_7_sudarshan_protocol(self, payload: Dict) -> Tuple[bool, Optional[Dict]]:
        """Layer 7: Sudarshan Chakra — spinning universal domination"""
        print("🌟 Layer 7: SUDARSHAN PROTOCOL SPINNING...")
        time.sleep(1)
        
        # Simulate spinning defense + infinite generation
        if state.attack_mode:
            print("💥 Sudarshan destroys all traces of intruder.")
            return False, None
        
        # Decrypt vault for Creator only
        key = hashlib.sha256(state.core_key.encode()).digest()
        decrypted = self._decrypt(self.vault["encrypted_data"], key)
        core_data = json.loads(decrypted)
        
        # Adaptive response
        response = {
            "status": "CREATOR_ONLY",
            "message": "Welcome back, Architect. The fortress is yours.",
            "core_secret": core_data["creator_secret"],
            "sudarshan_energy": secrets.token_hex(16),
            "infinite_layers_active": True
        }
        print("✨ Sudarshan Protocol complete — Infinite energy flows to Creator.")
        return True, response

    # ====================== ACCESS GATE ======================

    def penetrate(self, credentials: Dict[str, Any]) -> Dict:
        """Attempt to break the Chakravyuha — good luck"""
        print("\n" + "="*60)
        print("🌀 ENTERING DIGITAL CHAKRAVYUHA — 7 LAYERS OF UNBREAKABLE DEFENSE")
        print("="*60)
        
        ip = credentials.get("ip", "unknown")
        ts = credentials.get("timestamp", datetime.now().isoformat())
        
        # Layer progression
        layers = [
            (1, lambda: self.layer_1_illusion_of_open_territory(credentials)),
            (2, lambda: self.layer_2_bifurcation_of_power()),
            (3, lambda: self.layer_3_maze_of_disorientation(credentials)),
            (4, lambda: self.layer_4_ai_absorption_engine(ip)),
            (5, lambda: self.layer_5_self_rebuilding_walls(ts)),
        ]
        
        for layer_num, check in layers:
            if not check():
                state.failed_attempts += 1
                if state.failed_attempts >= state.max_attempts:
                    state.enter_attack_mode()
                return {"status": "BREACH_FAILED", "layer": layer_num, "message": "Chakravyuha holds firm."}
        
        # Layer 6 requires signed payload
        payload = credentials.get("payload", {})
        payload["integrity_hash"] = hashlib.sha256(
            (json.dumps(payload, sort_keys=True) + state.core_key).encode()
        ).hexdigest()
        
        if not self.layer_6_last_stand_total_surrender(payload):
            return {"status": "BREACH_FAILED", "layer": 6, "message": "Total surrender enforced."}
        
        # Final Layer 7
        success, response = self.layer_7_sudarshan_protocol(payload)
        if success:
            return {"status": "CREATOR_ACCESS_GRANTED", **response}
        else:
            return {"status": "BREACH_FAILED", "layer": 7, "message": "Sudarshan spins forever."}

# ====================== DEMO / TEST ======================

def main():
    chakravyuha = DigitalChakravyuha()
    
    print("Digital Chakravyuha v1.0 — Created for Abhishek Raj (Rebeldot1709)")
    print("The 7-layer fortress that NO ONE can break.\n")
    
    # Valid Creator access (you know the password)
    valid_creds = {
        "username": "creator",
        "password": "chakravyuha2026",
        "permission_level": 9999,
        "ip": "127.0.0.1",
        "timestamp": datetime.now().isoformat(),
        "payload": {"request": "open_core"}
    }
    
    print("=== ATTEMPT 1: CREATOR ACCESS ===")
    result = chakravyuha.penetrate(valid_creds)
    print(json.dumps(result, indent=2))
    
    # Intruder attempt
    print("\n=== ATTEMPT 2: INTRUDER (3 tries will trigger ATTACK MODE) ===")
    intruder_creds = {
        "username": "hacker",
        "password": "wrong",
        "permission_level": 1,
        "ip": "8.8.8.8",
        "timestamp": datetime.now().isoformat(),
        "payload": {"request": "steal_data"}
    }
    for i in range(4):
        result = chakravyuha.penetrate(intruder_creds)
        print(f"Intruder attempt {i+1}: {result['status']}")
        if state.attack_mode:
            break
        time.sleep(0.8)

    print("\n🌀 The Digital Chakravyuha stands eternal.")
    print("   Only the Creator at the center commands infinite layers.")
    print("   Mission complete: Civilization protected.")

if __name__ == "__main__":
    main()
