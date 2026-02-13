# ==========================================================
# M-HTDP: Modular HSM Tamper Detection & Telemetry Platform
# Architecture-Aligned Simulation Version
# FIPS 140-3 Level 3+ Tamper Detection Model
# ==========================================================

import time
import json
import random
import hashlib
from datetime import datetime

# Crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# ==========================================================
# CONFIGURATION
# ==========================================================

TELEMETRY_INTERVAL = 1
CRITICAL_THRESHOLD = 100

# ==========================================================
# HSM STATE (Secure Processing Domain)
# ==========================================================

class HSMState:
    def __init__(self):
        self.lockdown = False
        self.zeroized = False

    def trigger_zeroization(self):
        self.zeroized = True
        self.lockdown = True
        print("\n[HIGH-CONFIDENCE ALERT]")
        print("[RESPONSE] 🔥 CRITICAL TAMPER DETECTED")
        print("[ACTION] Cryptographic Keys ZEROIZED")
        print("[STATE] HSM LOCKDOWN MODE ACTIVATED\n")

# ==========================================================
# SECURE LOGGING ENGINE (Append-Only Hash Chain + RSA)
# ==========================================================

class SecureLog:
    def __init__(self):
        self.chain = []
        self.previous_hash = "0"

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        self.public_key = self.private_key.public_key()

    def append(self, event):
        event_string = json.dumps(event, sort_keys=True)
        combined = event_string + self.previous_hash
        current_hash = hashlib.sha256(combined.encode()).hexdigest()

        signature = self.private_key.sign(
            current_hash.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        entry = {
            "event": event,
            "previous_hash": self.previous_hash,
            "current_hash": current_hash,
            "signature": signature.hex()
        }

        self.chain.append(entry)
        self.previous_hash = current_hash

    def verify_chain(self):
        prev = "0"
        for entry in self.chain:
            event_string = json.dumps(entry["event"], sort_keys=True)
            combined = event_string + prev
            recalculated = hashlib.sha256(combined.encode()).hexdigest()

            if recalculated != entry["current_hash"]:
                return False

            try:
                self.public_key.verify(
                    bytes.fromhex(entry["signature"]),
                    entry["current_hash"].encode(),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except:
                return False

            prev = entry["current_hash"]

        return True

# ==========================================================
# TELEMETRY ENGINE (Sensor Domain Simulation)
# ==========================================================

class TelemetryEngine:
    def __init__(self):
        self.active_attacks = []

    def inject_attack(self, attack_type):
        self.active_attacks.append(attack_type)

    def clear_attacks(self):
        self.active_attacks = []

    def generate(self):
        timestamp = datetime.now().astimezone().isoformat()

        # Normal baseline
        voltage = random.uniform(4.8, 5.2)
        light = random.uniform(0, 5)
        temperature = random.uniform(30, 40)
        timing = random.uniform(0.99, 1.01)

        triggered = []

        for attack in self.active_attacks:

            if attack == "VOLTAGE_GLITCH":
                voltage = random.uniform(1.5, 2.5)
                triggered.append("Voltage Fault Injection")

            if attack == "LIGHT_EXPOSURE":
                light = random.uniform(50, 100)
                triggered.append("Enclosure Breach")

            if attack == "EM_PULSE":
                timing = random.uniform(0.80, 0.90)
                triggered.append("EM Fault Injection")

            if attack == "LASER_FAULT":
                temperature = random.uniform(70, 90)
                triggered.append("Laser Tamper")

        return {
            "timestamp": timestamp,
            "voltage": round(voltage, 2),
            "light": round(light, 2),
            "temperature": round(temperature, 2),
            "timing": round(timing, 4),
            "triggered_attacks": triggered if triggered else ["NORMAL"]
        }

# ==========================================================
# DETECTION & CORRELATION ENGINE
# ==========================================================

class DetectionEngine:
    def __init__(self, hsm_state):
        self.hsm_state = hsm_state

    def evaluate(self, telemetry):
        score = 0
        reasons = []

        if telemetry["voltage"] < 3:
            score += 30
            reasons.append("Voltage Anomaly")

        if telemetry["light"] > 20:
            score += 25
            reasons.append("Optical Tamper")

        if telemetry["timing"] < 0.95:
            score += 30
            reasons.append("Timing Fault")

        if telemetry["temperature"] > 60:
            score += 35
            reasons.append("Thermal Fault")

        if len(reasons) >= 2:
            score += 40
            reasons.append("Multi-Signal Correlated Attack")

        if len(reasons) >= 3:
            score += 20
            reasons.append("High-Confidence Composite Attack")

        severity = "LOW"
        if score > 40:
            severity = "MEDIUM"
        if score > 70:
            severity = "HIGH"
        if score >= CRITICAL_THRESHOLD:
            severity = "CRITICAL"
            self.hsm_state.trigger_zeroization()

        return {
            "risk_score": score,
            "severity": severity,
            "reasons": reasons
        }

# ==========================================================
# COMPLIANCE REPORT
# ==========================================================

def generate_compliance_report(log, hsm_state):
    report = {
        "FIPS_Target": "FIPS 140-3 Level 3+ (Simulated)",
        "Total_Events": len(log.chain),
        "Log_Integrity_Verified": log.verify_chain(),
        "Zeroization_Triggered": hsm_state.zeroized,
        "Timestamp": datetime.now().astimezone().isoformat()
    }

    print("\n===== COMPLIANCE REPORT =====")
    print(json.dumps(report, indent=4))
    print("=============================\n")

# ==========================================================
# SIEM EXPORT SIMULATION
# ==========================================================

def export_to_siem(event):
    payload = {
        "siem_timestamp": datetime.now().astimezone().isoformat(),
        "event": event
    }

    print("[SIEM EXPORT] Event transmitted to Enterprise SOC")
    print(json.dumps(payload, indent=2))

# ==========================================================
# SYSTEM INITIALIZATION
# ==========================================================

hsm_state = HSMState()
secure_log = SecureLog()
telemetry_engine = TelemetryEngine()
detection_engine = DetectionEngine(hsm_state)

# ==========================================================
# MAIN SIMULATION LOOP
# ==========================================================

def run_simulation(duration=5):
    for _ in range(duration):

        telemetry = telemetry_engine.generate()
        analysis = detection_engine.evaluate(telemetry)

        record = {
            "telemetry": telemetry,
            "analysis": analysis
        }

        secure_log.append(record)

        print("\n--- Telemetry Event ---")
        print(json.dumps(record, indent=2))

        if analysis["severity"] in ["HIGH", "CRITICAL"]:
            export_to_siem(record)

        time.sleep(TELEMETRY_INTERVAL)

    print("\nLog Integrity Verified:", secure_log.verify_chain())

# ==========================================================
# EXECUTION ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    print("M-HTDP Architecture-Aligned Simulation Ready\n")

    print("Running Normal Simulation...\n")
    run_simulation(3)

    print("\nInjecting Composite Attack...\n")
    telemetry_engine.inject_attack("VOLTAGE_GLITCH")
    telemetry_engine.inject_attack("LIGHT_EXPOSURE")
    telemetry_engine.inject_attack("EM_PULSE")
    telemetry_engine.inject_attack("LASER_FAULT")

    run_simulation(3)

    print("\nGenerating Compliance Report...\n")
    generate_compliance_report(secure_log, hsm_state)
