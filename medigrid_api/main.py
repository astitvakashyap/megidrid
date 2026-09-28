"""
MedGrid Health Records API
----------------------------
A synthetic, deliberately vulnerable REST API built as a scanning target
for PathFinder AI. Not a real product, no real patient data. Run locally
/ in an isolated lab only - do not expose to the public internet.

Run it:
    pip install -r requirements.txt
    python run.py

Then point PathFinder's "Target API base URL" at:
    http://0.0.0.0:9100

See README.md for the exact values to paste into PathFinder's scan form.

This target is built around ONE continuous, easy-to-track 10-hop BOLA /
data-exposure chain (OWASP API1 + API3), plus one independent Broken
Auth / BFLA finding for variety.
"""

from typing import Optional, Dict, Any
from fastapi import FastAPI, Header, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware

from . import database as db

app = FastAPI(
    title="MedGrid Health Records API",
    description="Synthetic target API for API security scanning demos. Not a real service, no real patient data.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or malformed Authorization header")
    token = authorization[7:].strip()
    username = db.TOKEN_TO_USER.get(token)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or unrecognized token")
    return db.USERS[username]


def get_current_user_optional(authorization: Optional[str] = Header(default=None)) -> Optional[Dict[str, Any]]:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization[7:].strip()
    username = db.TOKEN_TO_USER.get(token)
    return db.USERS.get(username) if username else None


def _check_owner(record: Dict[str, Any], current_user: Dict[str, Any], patch_flag: str):
    if db.PATCH_SETTINGS[patch_flag] and record["owner"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="Forbidden: you do not have access to this record")


# ---------------------------------------------------------------------
# Infra
# ---------------------------------------------------------------------
@app.get("/")
def root():
    return {"service": "MedGrid Health Records API", "status": "online", "version": "1.0.0"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/v1/me")
def whoami(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Caller's own profile. Used by PathFinder to auto-harvest the
    victim's real patient_id when scanning with Actor B's token."""
    return current_user


# ---------------------------------------------------------------------
# The chain - registered in this exact order so the first successful
# hop's leaked identifier is available before the next hop is tested.
# ---------------------------------------------------------------------
@app.get("/api/v2/patients/{patient_id}")
def get_patient(patient_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = db.PATIENTS.get(patient_id)
    if not record:
        raise HTTPException(status_code=404, detail="Patient not found")
    _check_owner(record, current_user, "FIX_PATIENTS_BOLA")
    return record


@app.get("/api/v2/appointments/{appointment_id}")
def get_appointment(appointment_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = db.APPOINTMENTS.get(appointment_id)
    if not record:
        raise HTTPException(status_code=404, detail="Appointment not found")
    _check_owner(record, current_user, "FIX_APPOINTMENTS_BOLA")
    return record


@app.get("/api/v2/lab-orders/{lab_order_id}")
def get_lab_order(lab_order_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = db.LAB_ORDERS.get(lab_order_id)
    if not record:
        raise HTTPException(status_code=404, detail="Lab order not found")
    _check_owner(record, current_user, "FIX_LAB_ORDERS_BOLA")
    return record


@app.get("/api/v2/lab-results/{lab_result_id}")
def get_lab_result(lab_result_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = db.LAB_RESULTS.get(lab_result_id)
    if not record:
        raise HTTPException(status_code=404, detail="Lab result not found")
    _check_owner(record, current_user, "FIX_LAB_RESULTS_BOLA")
    return record


@app.get("/api/v2/prescriptions/{prescription_id}")
def get_prescription(prescription_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = db.PRESCRIPTIONS.get(prescription_id)
    if not record:
        raise HTTPException(status_code=404, detail="Prescription not found")
    _check_owner(record, current_user, "FIX_PRESCRIPTIONS_BOLA")
    return record


@app.get("/api/v2/pharmacy/fulfillments/{fulfillment_id}")
def get_fulfillment(fulfillment_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = db.FULFILLMENTS.get(fulfillment_id)
    if not record:
        raise HTTPException(status_code=404, detail="Fulfillment not found")
    _check_owner(record, current_user, "FIX_FULFILLMENTS_BOLA")
    return record


@app.get("/api/v2/insurance/claims/{claim_id}")
def get_claim(claim_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = db.INSURANCE_CLAIMS.get(claim_id)
    if not record:
        raise HTTPException(status_code=404, detail="Claim not found")
    _check_owner(record, current_user, "FIX_CLAIMS_BOLA")
    return record


@app.get("/api/v2/billing/invoices/{invoice_id}")
def get_invoice(invoice_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = db.BILLING_INVOICES.get(invoice_id)
    if not record:
        raise HTTPException(status_code=404, detail="Invoice not found")
    _check_owner(record, current_user, "FIX_INVOICES_BOLA")
    return record


@app.get("/api/v2/payments/{payment_id}")
def get_payment(payment_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Leaks a 'card_token' field - PathFinder classifies this hop as
    Excessive Data Exposure rather than plain BOLA."""
    record = db.PAYMENTS.get(payment_id)
    if not record:
        raise HTTPException(status_code=404, detail="Payment not found")
    _check_owner(record, current_user, "FIX_PAYMENTS_DATA_EXPOSURE")
    return record


@app.get("/api/v2/emergency-contacts/{emergency_contact_id}")
def get_emergency_contact(emergency_contact_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """End of the chain: leaks a 'contact_private_phone' field - a
    second Data Exposure finding, the worst-case compromised asset."""
    record = db.EMERGENCY_CONTACTS.get(emergency_contact_id)
    if not record:
        raise HTTPException(status_code=404, detail="Emergency contact not found")
    _check_owner(record, current_user, "FIX_EMERGENCY_CONTACTS_DATA_EXPOSURE")
    return record


# ---------------------------------------------------------------------
# One independent (non-chain) flaw for variety: no auth check at all.
# ---------------------------------------------------------------------
@app.get("/api/v2/admin/staff/directory")
def admin_staff_directory(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """No auth enforcement at all - triggers both Broken Authentication
    (works with zero token) and BFLA (works with a non-admin token)."""
    if db.PATCH_SETTINGS["FIX_STAFF_DIRECTORY_OPEN_ACCESS"]:
        if not current_user or current_user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Admin role required")
    return {"staff": db.STAFF_DIRECTORY}
