#!/usr/bin/env python3
"""Local web UI for the Password Security Tool (Python standard library only)."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import json
import os
import threading
import webbrowser

from password_tool import (
    DEFAULT_WORDLIST, calculate_entropy, evaluate_strength,
    hash_password, sha256_fingerprint, verify_password, load_dictionary,
)

ROOT = Path(__file__).resolve().parent
WORDLIST = load_dictionary(DEFAULT_WORDLIST)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / "static"), **kwargs)

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path not in ("/api/analyze", "/api/hash", "/api/verify"):
            return self.send_json(404, {"error": "Not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16_384:
                return self.send_json(413, {"error": "Request too large"})
            data = json.loads(self.rfile.read(length) or b"{}")
            password = data.get("password", "")
            if not isinstance(password, str):
                return self.send_json(400, {"error": "Password must be text"})

            if self.path == "/api/analyze":
                label, feedback = evaluate_strength(password, WORDLIST)
                return self.send_json(200, {
                    "strength": label,
                    "entropy": calculate_entropy(password),
                    "length": len(password),
                    "checks": {
                        "length": len(password) >= 8,
                        "uppercase": any(c.isupper() for c in password),
                        "lowercase": any(c.islower() for c in password),
                        "digit": any(c.isdigit() for c in password),
                        "symbol": any(not c.isalnum() for c in password),
                    },
                    "feedback": feedback,
                    "sha256": sha256_fingerprint(password) if password else "",
                })

            if self.path == "/api/hash":
                algorithm = data.get("algorithm", "scrypt")
                if not password:
                    return self.send_json(400, {"error": "Enter a password first"})
                if algorithm == "scrypt":
                    encoded = hash_password(password)
                    return self.send_json(200, {"hash": encoded, "algorithm": "scrypt", "bits": 256})
                if algorithm == "sha256":
                    return self.send_json(200, {
                        "hash": sha256_fingerprint(password), "algorithm": "SHA-256", "bits": 256
                    })
                return self.send_json(400, {"error": "Unsupported algorithm"})

            encoded_hash = data.get("hash", "")
            if not isinstance(encoded_hash, str):
                return self.send_json(400, {"error": "Hash must be text"})
            return self.send_json(200, {"verified": verify_password(password, encoded_hash)})
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self.send_json(400, {"error": str(exc)})
        except Exception:
            return self.send_json(500, {"error": "Unexpected server error"})


if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8080

    print("Starting CipherLab...")

    try:
        with ThreadingHTTPServer((host, port), Handler) as server:
            print(f"Server running at http://{host}:{port}")
            print("Press Ctrl+C to stop.")
            server.serve_forever()

    except KeyboardInterrupt:
        print("\nServer stopped.")

    except OSError as e:
        print(f"Server error: {e}")
    host, port = "127.0.0.1", 8080

    try:
        server = ThreadingHTTPServer((host, port), Handler)
        print(f"\nPassword Security Tool running at http://{host}:{port}")
        print("Press Ctrl+C to stop.")

        server.serve_forever()

    except OSError as e:
        print(f"Server could not start: {e}")

    except KeyboardInterrupt:
        print("\nShutting down...")

    finally:
        if 'server' in locals():
            server.server_close()
    print(f"\nPassword Security Tool is running at http://{host}:{port}")
    print("Local-only development server. Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.server_close()
