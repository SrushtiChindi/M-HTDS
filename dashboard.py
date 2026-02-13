from flask import Flask, render_template_string, request
import json
from mhtdp_simulation import (
    HSMState,
    SecureLog,
    TelemetryEngine,
    DetectionEngine
)

app = Flask(__name__)

# Initialize system
hsm_state = HSMState()
secure_log = SecureLog()
telemetry_engine = TelemetryEngine()
detection_engine = DetectionEngine(hsm_state)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>M-HTDP Dashboard</title>
</head>
<body>
    <h1>🔐 M-HTDP Live Dashboard</h1>

    <form method="post">
        <h3>Inject Attacks:</h3>
        <input type="checkbox" name="attack" value="VOLTAGE_GLITCH"> Voltage Glitch<br>
        <input type="checkbox" name="attack" value="LIGHT_EXPOSURE"> Light Exposure<br>
        <input type="checkbox" name="attack" value="EM_PULSE"> EM Pulse<br>
        <input type="checkbox" name="attack" value="LASER_FAULT"> Laser Fault<br><br>
        <input type="submit" value="Run Simulation">
    </form>

    <hr>

    {% if result %}
        <h3>Telemetry:</h3>
        <pre>{{ result }}</pre>

        <h3 style="color:{{ color }}">Severity: {{ severity }}</h3>

        <h4>HSM Status: {{ status }}</h4>
        <h4>Log Integrity: {{ integrity }}</h4>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def dashboard():

    result = None
    severity = None
    color = "green"
    status = "Operational"
    integrity = secure_log.verify_chain()

    if request.method == "POST":
        telemetry_engine.clear_attacks()
        attacks = request.form.getlist("attack")

        for attack in attacks:
            telemetry_engine.inject_attack(attack)

        telemetry = telemetry_engine.generate()
        analysis = detection_engine.evaluate(telemetry)

        record = {
            "telemetry": telemetry,
            "analysis": analysis
        }

        secure_log.append(record)

        result = json.dumps(record, indent=2)
        severity = analysis["severity"]

        color_map = {
            "LOW": "green",
            "MEDIUM": "orange",
            "HIGH": "red",
            "CRITICAL": "darkred"
        }

        color = color_map.get(severity, "green")

        if hsm_state.lockdown:
            status = "🔴 LOCKDOWN ACTIVE"

        integrity = secure_log.verify_chain()

    return render_template_string(
        HTML_TEMPLATE,
        result=result,
        severity=severity,
        color=color,
        status=status,
        integrity=integrity
    )

if __name__ == "__main__":
    app.run(debug=True)
