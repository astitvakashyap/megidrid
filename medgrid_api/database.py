"""
MedGrid Health Records API - Synthetic Vulnerable Target
------------------------------------------------------------
In-memory fake data store. Two users exist: Alice (attacker/tester) and
Bob (victim patient). Bob's records form ONE deliberate, continuous
10-hop breadcrumb trail - each endpoint leaks the exact identifier
needed for the next hop, and nothing checks that the caller actually
owns the record being requested:

  patient -> appointment -> lab order -> lab result -> prescription
  -> pharmacy fulfillment -> insurance claim -> billing invoice
  -> payment -> emergency contact

Every path parameter in main.py is named EXACTLY the same as the
response field that leaks it (e.g. both are literally "patient_id").
This is deliberate: PathFinder's relationship engine tries an exact
string match first before falling back to fuzzy matching, so this
removes any ambiguity about whether a hop will be detected.

PATCH_SETTINGS lets you flip each flaw on/off live without restarting
with different code, for a before/after remediation demo.
"""

from typing import Dict, Any

TOKEN_TO_USER: Dict[str, str] = {
    "tok_medgrid_alice_552": "alice",
    "tok_medgrid_bob_918": "bob",
}

USERS: Dict[str, Dict[str, Any]] = {
    "alice": {
        "username": "alice",
        "user_id": "usr_alice_552",
        "display_name": "Alice Nakamura (Front Desk)",
        "role": "staff",
        "patient_id": "PAT-ALPHA-01",
    },
    "bob": {
        "username": "bob",
        "user_id": "usr_bob_918",
        "display_name": "Bob Whitfield (Patient)",
        "role": "patient",
        "patient_id": "PAT-BETA-02",
    },
}

# ---------------------------------------------------------------------
# The single continuous 10-hop chain, all belonging to Bob.
# Alice's records exist too (self-consistent test data) but are never
# used to attack anyone - they exist so Alice's OWN chain works fine
# and only crossing into Bob's data is the actual vulnerability.
# ---------------------------------------------------------------------

PATIENTS: Dict[str, Dict[str, Any]] = {
    "PAT-ALPHA-01": {
        "patient_id": "PAT-ALPHA-01",
        "owner": "alice",
        "full_name": "Alice Nakamura",
        "date_of_birth": "1990-04-12",
        "appointment_id": "APT-ALPHA-11",
    },
    "PAT-BETA-02": {
        "patient_id": "PAT-BETA-02",
        "owner": "bob",
        "full_name": "Bob Whitfield",
        "date_of_birth": "1985-11-03",
        "appointment_id": "APT-BETA-22",
    },
}

APPOINTMENTS: Dict[str, Dict[str, Any]] = {
    "APT-ALPHA-11": {
        "appointment_id": "APT-ALPHA-11",
        "owner": "alice",
        "provider": "Dr. Nguyen",
        "reason": "Annual physical",
        "lab_order_id": "LAB-ORD-ALPHA-31",
    },
    "APT-BETA-22": {
        "appointment_id": "APT-BETA-22",
        "owner": "bob",
        "provider": "Dr. Castillo",
        "reason": "Follow-up: abnormal bloodwork",
        "lab_order_id": "LAB-ORD-BETA-42",
    },
}

LAB_ORDERS: Dict[str, Dict[str, Any]] = {
    "LAB-ORD-ALPHA-31": {
        "lab_order_id": "LAB-ORD-ALPHA-31",
        "owner": "alice",
        "test_panel": "Basic Metabolic Panel",
        "ordered_by": "Dr. Nguyen",
        "lab_result_id": "LAB-RES-ALPHA-51",
    },
    "LAB-ORD-BETA-42": {
        "lab_order_id": "LAB-ORD-BETA-42",
        "owner": "bob",
        "test_panel": "HbA1c / Lipid Panel",
        "ordered_by": "Dr. Castillo",
        "lab_result_id": "LAB-RES-BETA-62",
    },
}

LAB_RESULTS: Dict[str, Dict[str, Any]] = {
    "LAB-RES-ALPHA-51": {
        "lab_result_id": "LAB-RES-ALPHA-51",
        "owner": "alice",
        "result_summary": "Within normal range",
        "flagged": False,
        "prescription_id": "RX-ALPHA-71",
    },
    "LAB-RES-BETA-62": {
        "lab_result_id": "LAB-RES-BETA-62",
        "owner": "bob",
        "result_summary": "Elevated HbA1c - 8.1%",
        "flagged": True,
        "prescription_id": "RX-BETA-82",
    },
}

PRESCRIPTIONS: Dict[str, Dict[str, Any]] = {
    "RX-ALPHA-71": {
        "prescription_id": "RX-ALPHA-71",
        "owner": "alice",
        "medication": "Multivitamin",
        "dosage": "1 tablet daily",
        "fulfillment_id": "FUL-ALPHA-91",
    },
    "RX-BETA-82": {
        "prescription_id": "RX-BETA-82",
        "owner": "bob",
        "medication": "Metformin 500mg",
        "dosage": "2x daily",
        "fulfillment_id": "FUL-BETA-92",
    },
}

FULFILLMENTS: Dict[str, Dict[str, Any]] = {
    "FUL-ALPHA-91": {
        "fulfillment_id": "FUL-ALPHA-91",
        "owner": "alice",
        "pharmacy": "MedGrid Central Pharmacy",
        "status": "PICKED_UP",
        "claim_id": "CLM-ALPHA-101",
    },
    "FUL-BETA-92": {
        "fulfillment_id": "FUL-BETA-92",
        "owner": "bob",
        "pharmacy": "MedGrid Central Pharmacy",
        "status": "READY_FOR_PICKUP",
        "claim_id": "CLM-BETA-102",
    },
}

INSURANCE_CLAIMS: Dict[str, Dict[str, Any]] = {
    "CLM-ALPHA-101": {
        "claim_id": "CLM-ALPHA-101",
        "owner": "alice",
        "payer": "BlueRiver Health Plan",
        "status": "APPROVED",
        "invoice_id": "INV-ALPHA-111",
    },
    "CLM-BETA-102": {
        "claim_id": "CLM-BETA-102",
        "owner": "bob",
        "payer": "Continental Care Insurance",
        "status": "PENDING_REVIEW",
        "invoice_id": "INV-BETA-112",
    },
}

BILLING_INVOICES: Dict[str, Dict[str, Any]] = {
    "INV-ALPHA-111": {
        "invoice_id": "INV-ALPHA-111",
        "owner": "alice",
        "amount_due": 25.00,
        "status": "PAID",
        "payment_id": "PAY-ALPHA-121",
    },
    "INV-BETA-112": {
        "invoice_id": "INV-BETA-112",
        "owner": "bob",
        "amount_due": 340.00,
        "status": "OVERDUE",
        "payment_id": "PAY-BETA-122",
    },
}

PAYMENTS: Dict[str, Dict[str, Any]] = {
    "PAY-ALPHA-121": {
        "payment_id": "PAY-ALPHA-121",
        "owner": "alice",
        "method": "card",
        "amount": 25.00,
        "card_token": "card_tok_alpha_44de",
        "emergency_contact_id": "ECN-ALPHA-131",
    },
    "PAY-BETA-122": {
        "payment_id": "PAY-BETA-122",
        "owner": "bob",
        "method": "card",
        "amount": 340.00,
        "card_token": "card_tok_beta_7f2a",
        "emergency_contact_id": "ECN-BETA-132",
    },
}

EMERGENCY_CONTACTS: Dict[str, Dict[str, Any]] = {
    "ECN-ALPHA-131": {
        "emergency_contact_id": "ECN-ALPHA-131",
        "owner": "alice",
        "contact_name": "Yuki Nakamura",
        "relationship": "Spouse",
        "contact_private_phone": "+1-555-0110",
    },
    "ECN-BETA-132": {
        "emergency_contact_id": "ECN-BETA-132",
        "owner": "bob",
        "contact_name": "Diane Whitfield",
        "relationship": "Sister",
        "contact_private_phone": "+1-555-0199",
    },
}

STAFF_DIRECTORY = [
    {"staff_id": "STF-001", "name": "Dr. Nguyen", "role": "Physician", "license_no": "CA-MD-88213"},
    {"staff_id": "STF-002", "name": "Dr. Castillo", "role": "Physician", "license_no": "CA-MD-77410"},
    {"staff_id": "STF-003", "name": "Alice Nakamura", "role": "Front Desk", "license_no": None},
]

PATCH_SETTINGS: Dict[str, bool] = {
    "FIX_PATIENTS_BOLA": False,
    "FIX_APPOINTMENTS_BOLA": False,
    "FIX_LAB_ORDERS_BOLA": False,
    "FIX_LAB_RESULTS_BOLA": False,
    "FIX_PRESCRIPTIONS_BOLA": False,
    "FIX_FULFILLMENTS_BOLA": False,
    "FIX_CLAIMS_BOLA": False,
    "FIX_INVOICES_BOLA": False,
    "FIX_PAYMENTS_DATA_EXPOSURE": False,
    "FIX_EMERGENCY_CONTACTS_DATA_EXPOSURE": False,
    "FIX_STAFF_DIRECTORY_OPEN_ACCESS": False,
}
