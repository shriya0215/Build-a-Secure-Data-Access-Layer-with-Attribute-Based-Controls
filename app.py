from flask import Flask, render_template, jsonify, request
import sqlite3, json, os, datetime

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "shield_abac.db")

CLEARANCE = {"public": 1, "confidential": 2, "secret": 3}

PERSONAS = {
    "alice": {"id": "alice", "name": "Alice Chen", "email": "alice@acme.example", "tenant_id": "acme", "department": "finance", "region": "IN", "clearance": "confidential", "pii_access": False, "description": "Internal finance analyst"},
    "bob": {"id": "bob", "name": "Bob Miller", "email": "bob@partner.example", "tenant_id": "partner-1", "department": "partner", "region": "US", "clearance": "public", "pii_access": False, "description": "External partner analyst"},
    "carol": {"id": "carol", "name": "Carol Singh", "email": "carol@acme.example", "tenant_id": "*", "department": "security", "region": "IN", "clearance": "secret", "pii_access": True, "description": "Security auditor with broad tenant scope"},
}

RESOURCES = {
    "sales_summary": {"id": "sales_summary", "label": "Sales Summary", "tenant_id": "acme", "department": "finance", "region": "IN", "sensitivity": "confidential", "contains_pii": False, "rows": 12840, "description": "Aggregated monthly sales"},
    "customer_records": {"id": "customer_records", "label": "Customer Records", "tenant_id": "acme", "department": "sales", "region": "IN", "sensitivity": "secret", "contains_pii": True, "rows": 2450, "description": "Customer profile and contact data"},
    "partner_metrics": {"id": "partner_metrics", "label": "Partner Metrics", "tenant_id": "partner-1", "department": "partner", "region": "US", "sensitivity": "public", "contains_pii": False, "rows": 960, "description": "Shared partner performance metrics"},
    "support_tickets": {"id": "support_tickets", "label": "Support Tickets", "tenant_id": "acme", "department": "support", "region": "IN", "sensitivity": "confidential", "contains_pii": True, "rows": 5200, "description": "Support tickets with customer identifiers"},
}

POLICIES = [
    {"id": "P-001", "name": "Tenant isolation", "effect": "allow", "condition": "User tenant matches resource tenant, or user tenant is wildcard (*)", "active": True},
    {"id": "P-002", "name": "Sensitivity clearance", "effect": "allow", "condition": "User clearance level must be equal to or higher than resource sensitivity", "active": True},
    {"id": "P-003", "name": "Regional boundary", "effect": "allow", "condition": "User region matches resource region; security auditor may cross regions", "active": True},
    {"id": "P-004", "name": "PII protection", "effect": "allow", "condition": "PII fields are visible only when user has pii_access; otherwise output is masked", "active": True},
    {"id": "P-005", "name": "Write restriction", "effect": "allow", "condition": "Write actions require tenant match, department match, sufficient clearance, and business hours", "active": True},
]

SAMPLE_ROWS = {
    "sales_summary": [{"month":"2026-10","region":"IN","revenue":1250000,"orders":438},{"month":"2026-09","region":"IN","revenue":1185000,"orders":411},{"month":"2026-08","region":"IN","revenue":1092000,"orders":395}],
    "customer_records": [{"customer_id":"C-1001","name":"Aarav Patil","email":"aarav@example.com","city":"Mumbai","spend":72000},{"customer_id":"C-1002","name":"Meera Shah","email":"meera@example.com","city":"Pune","spend":54000},{"customer_id":"C-1003","name":"Rohan Das","email":"rohan@example.com","city":"Nashik","spend":31000}],
    "partner_metrics": [{"partner":"Northstar","quarter":"Q3","conversion":0.18,"tickets":42},{"partner":"BluePeak","quarter":"Q3","conversion":0.23,"tickets":37},{"partner":"Orion","quarter":"Q3","conversion":0.16,"tickets":51}],
    "support_tickets": [{"ticket":"T-901","customer_email":"client@example.com","category":"billing","status":"open","priority":"high"},{"ticket":"T-902","customer_email":"user@example.com","category":"login","status":"resolved","priority":"medium"},{"ticket":"T-903","customer_email":"person@example.com","category":"delivery","status":"open","priority":"low"}],
}

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_id TEXT, user_name TEXT,
            resource_id TEXT, action TEXT, decision TEXT, reason TEXT, policy_ids TEXT,
            tenant_id TEXT, region TEXT, environment TEXT
        )""")

def evaluate(user, resource, action, environment):
    reasons, matched = [], []
    tenant_ok = user["tenant_id"] == "*" or user["tenant_id"] == resource["tenant_id"]
    clearance_ok = CLEARANCE.get(user["clearance"], 0) >= CLEARANCE.get(resource["sensitivity"], 99)
    region_ok = user["region"] == resource["region"] or user["department"] == "security"
    pii_ok = not resource["contains_pii"] or user["pii_access"]
    if action in ("write", "delete"):
        business_hours = bool(environment.get("business_hours", False))
        dept_ok = user["department"] == resource["department"]
        # For write, wildcard tenant is not enough: explicit tenant ownership is required.
        tenant_ok = user["tenant_id"] == resource["tenant_id"]
        reasons += [f"Tenant match: {'PASS' if tenant_ok else 'FAIL'}", f"Department match: {'PASS' if dept_ok else 'FAIL'}", f"Business-hours condition: {'PASS' if business_hours else 'FAIL'}"]
        if tenant_ok and dept_ok and clearance_ok and business_hours:
            matched.append("P-005")
            decision = "ALLOW"
        else:
            decision = "DENY"
    else:
        reasons += [f"Tenant boundary: {'PASS' if tenant_ok else 'FAIL'}", f"Clearance ({user['clearance']}): {'PASS' if clearance_ok else 'FAIL'}", f"Region boundary: {'PASS' if region_ok else 'FAIL'}"]
        if tenant_ok: matched.append("P-001")
        if clearance_ok: matched.append("P-002")
        if region_ok: matched.append("P-003")
        if tenant_ok and clearance_ok and region_ok:
            decision = "ALLOW"
        else:
            decision = "DENY"
        if resource["contains_pii"]:
            reasons.append(f"PII access: {'PASS' if pii_ok else 'MASKED'}")
            if pii_ok: matched.append("P-004")
    if action not in ("read", "write", "delete"):
        decision, reasons = "DENY", ["Unsupported action"]
    return decision, reasons, matched, pii_ok

def audit(user, resource, action, decision, reasons, policy_ids, environment):
    with connect() as db:
        db.execute("INSERT INTO audit_log(timestamp,user_id,user_name,resource_id,action,decision,reason,policy_ids,tenant_id,region,environment) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (datetime.datetime.now().isoformat(timespec="seconds"), user["id"], user["name"], resource["id"], action, decision, " | ".join(reasons), json.dumps(policy_ids), user["tenant_id"], user["region"], json.dumps(environment)))

@app.route("/")
def home():
    init_db()
    return render_template("index.html", personas=PERSONAS, resources=RESOURCES, policies=POLICIES)

@app.get("/api/overview")
def overview():
    init_db()
    with connect() as db:
        total = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        allowed = db.execute("SELECT COUNT(*) FROM audit_log WHERE decision='ALLOW'").fetchone()[0]
        denied = total - allowed
        recent = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 8").fetchall()
    return jsonify({"total": total, "allowed": allowed, "denied": denied, "recent": [dict(r) for r in recent]})

@app.post("/api/evaluate")
def evaluate_api():
    payload = request.get_json(force=True)
    user = PERSONAS.get(payload.get("user_id"))
    resource = RESOURCES.get(payload.get("resource_id"))
    action = payload.get("action", "read")
    environment = {"business_hours": bool(payload.get("business_hours", False)), "ip": payload.get("ip", "192.168.1.20"), "device": payload.get("device", "Managed laptop")}
    if not user or not resource:
        return jsonify({"error": "Select a valid persona and resource"}), 400
    decision, reasons, policy_ids, pii_ok = evaluate(user, resource, action, environment)
    audit(user, resource, action, decision, reasons, policy_ids, environment)
    rows = SAMPLE_ROWS[resource["id"]] if decision == "ALLOW" and action == "read" else []
    if rows and resource["contains_pii"] and not pii_ok:
        rows = [{k: ("••••••" if k in ("email", "customer_email", "name") else v) for k, v in row.items()} for row in rows]
    return jsonify({"decision": decision, "user": user, "resource": resource, "action": action, "reasons": reasons, "policy_ids": policy_ids, "rows": rows, "environment": environment, "masked": bool(rows and resource["contains_pii"] and not pii_ok)})

@app.get("/api/audit")
def audit_api():
    init_db()
    with connect() as db:
        rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/audit/clear")
def clear_audit():
    with connect() as db:
        db.execute("DELETE FROM audit_log")
    return jsonify({"ok": True})

if __name__ == "__main__":
    init_db()
    app.run(debug=False, port=5000)
