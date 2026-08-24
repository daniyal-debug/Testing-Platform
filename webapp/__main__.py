"""Run the web app: ``python -m webapp`` (honours PORT env var)."""
import os

from .app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"APK Sentinel web UI running at http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
