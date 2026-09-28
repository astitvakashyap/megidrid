# MedGrid Health Records API

A synthetic, deliberately vulnerable REST API built to be scanned by
PathFinder AI. Not a real product, no real patient data. Run it locally
/ in an isolated lab only.

## Run it

```bash
pip install -r requirements.txt
python run.py
```

Starts the API at **http://127.0.0.1:9100**
(OpenAPI spec at `http://127.0.0.1:9100/openapi.json`).

Different port: `PORT=9200 python run.py`

## What's in it

One single, continuous, easy-to-track **10-node / 9-hop** chain - no
branches, no dead ends, every hop leads directly into the next:

```
/api/v2/patients/{patient_id}
  -> /api/v2/appointments/{appointment_id}
  -> /api/v2/lab-orders/{lab_order_id}
  -> /api/v2/lab-results/{lab_result_id}
  -> /api/v2/prescriptions/{prescription_id}
  -> /api/v2/pharmacy/fulfillments/{fulfillment_id}
  -> /api/v2/insurance/claims/{claim_id}
  -> /api/v2/billing/invoices/{invoice_id}
  -> /api/v2/payments/{payment_id}                    [leaks a card token]
  -> /api/v2/emergency-contacts/{emergency_contact_id} [leaks a private phone]
```

Design choice for reliability: every path parameter is named **exactly**
like the response field that leaks it - both are literally
`patient_id`, both are literally `appointment_id`, and so on. That
means PathFinder's relationship engine links every hop with a direct,
unambiguous exact-string match instead of a fuzzy guess.

Plus one independent finding for variety: `GET /api/v2/admin/staff/directory`
has no auth check at all (fires both Broken Authentication and BFLA).

**Verified by actually running PathFinder's scanner against this API:**
14 findings, **9 out of 9 candidate relationships confirmed
(100%)**, and **one single unbroken 9-hop attack path** covering
all 10 chain endpoints in exact order.

## Exact config to paste into PathFinder's "Start New Scan" form

| Field | Value |
|---|---|
| Target API base URL | `http://127.0.0.1:9100` |
| OpenAPI spec path | `/openapi.json` |
| Actor A token (Alice / attacker) | `tok_medgrid_alice_552` |
| Actor B token (Bob / victim) | `tok_medgrid_bob_918` |
| Actor A name | `Alice (Attacker/Tester)` |
| Actor B name | `Bob (Victim Patient)` |
| Actor A ID | `PAT-ALPHA-01` |
| Actor B ID | `PAT-BETA-02` |
| Resource seeds | leave empty (auto-harvested from `/api/v1/me`) |
| Profile paths | leave default (`/api/v1/me` is already in PathFinder's default list) |

Double-check the Target API base URL is reachable before you start the
scan: `curl http://127.0.0.1:9100/openapi.json` should return a big
JSON blob with a `paths` key. If it doesn't, the API isn't running (or
you're pointing at the wrong port) and the scan will silently fall
back to a generic 1-endpoint probe list instead of finding this chain.

## Live "patch and re-scan" demo

Every hop has an on/off switch in `medgrid_api/database.py`:

```python
PATCH_SETTINGS = {
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
```

Flip any hop to `True`, restart the server, and re-scan - you'll see
that specific finding disappear and the chain snap in two right at
that point. Good for a live "one fix breaks the whole path" demo.

## Safety note

No real security here by design. Don't deploy this anywhere reachable
from the public internet.