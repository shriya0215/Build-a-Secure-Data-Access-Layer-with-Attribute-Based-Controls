# SHIELD — Attribute-Based Secure Data Access Layer

A local educational demo of Attribute-Based Access Control (ABAC) for a multi-tenant analytics platform.

## Run on Windows
1. Extract the ZIP.
2. Open the extracted folder.
3. Click the folder address bar, type `cmd`, press Enter.
4. Run:
   `py -m pip install -r requirements.txt`
5. Run:
   `py app.py`
6. Open `http://127.0.0.1:5000`

## Demonstration
- Choose a persona, data table, action and environment.
- Click **Evaluate access** to see Allow/Deny, rule checks, policy IDs and sample data.
- PII is masked in the response if the persona lacks `pii_access`.
- Audit entries are persisted in SQLite (`shield_abac.db`).

## Personas
- Alice: Acme finance analyst, India, confidential clearance.
- Bob: external partner, partner-1 tenant, US, public clearance.
- Carol: security auditor, wildcard tenant scope, India, secret clearance, PII access.

## Note
This is a local classroom simulation. It is not production authentication or authorization; persona selection is a demo control and should not be used to protect real data.
