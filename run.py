"""
Convenience launcher for the MedGrid Health Records synthetic target API.

    python run.py

Starts the API on http://0.0.0.0:9100 (override with PORT env var).
"""
import os
import uvicorn

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "9100"))
    print(f"\nMedGrid Health Records API starting at http://{host}:{port}")
    print(f"OpenAPI spec at http://{host}:{port}/openapi.json")
    print("Point PathFinder's 'Target API base URL' at the address above.\n")
    uvicorn.run("medgrid_api.main:app", host=host, port=port, reload=False)