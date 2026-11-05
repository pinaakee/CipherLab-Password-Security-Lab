#!/usr/bin/env python3
"""Local-only web UI for CipherLab Password Security Lab."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import hashlib, json, secrets, string, urllib.request, urllib.error, math, re, os
from password_tool import DEFAULT_WORDLIST, calculate_entropy, evaluate_strength, hash_password, sha256_fingerprint, verify_password, load_dictionary
ROOT = Path(__file__).resolve().parent
WORDLIST = load_dictionary(DEFAULT_WORDLIST)
HIBP_URL = "https://api.pwnedpasswords.com/range/"

def hibp_match(password: str, response_text: str) -> int:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    suffix = digest[5:]
    for line in response_text.splitlines():
        try:
            candidate, count = line.strip().split(":", 1)
            if candidate.upper() == suffix: return int(count)
        except (ValueError, TypeError): continue
    return 0

def check_breach(password: str) -> dict:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    request = urllib.request.Request(HIBP_URL + digest[:5], headers={"Add-Padding":"true", "User-Agent":"CipherLab-Password-Security-Lab"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read(2_000_000).decode("utf-8", errors="replace")
    count = hibp_match(password, body)
    return {"found":count > 0, "count":count, "privacy":"Only the first 5 characters of a SHA-1 hash were sent; the password and full hash were not."}

def generate_password(length=20):
    length = max(12, min(int(length), 64))
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}?"
    chars = [secrets.choice(string.ascii_lowercase), secrets.choice(string.ascii_uppercase), secrets.choice(string.digits), secrets.choice("!@#$%^&*()-_=+[]{}?")]
    chars.extend(secrets.choice(alphabet) for _ in range(length-4))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs): super().__init__(*args, directory=str(ROOT/"static"), **kwargs)
    def send_json(self, status, payload):
        body=json.dumps(payload).encode(); self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        if self.path not in ("/api/analyze","/api/hash","/api/verify","/api/breach","/api/generate"): return self.send_json(404,{"error":"Not found"})
        try:
            length=int(self.headers.get("Content-Length","0"))
            if length>16384: return self.send_json(413,{"error":"Request too large"})
            data=json.loads(self.rfile.read(length) or b"{}"); password=data.get("password","")
            if not isinstance(password,str): return self.send_json(400,{"error":"Password must be text"})
            if self.path=="/api/analyze":
                label,feedback=evaluate_strength(password,WORDLIST); entropy=calculate_entropy(password); pool=0
                for pattern,size in ((r"[a-z]",26),(r"[A-Z]",26),(r"[0-9]",10),(r"[^a-zA-Z0-9]",33)):
                    if re.search(pattern,password): pool+=size
                guesses=pool**len(password) if password and pool else 0; seconds=guesses/10_000_000_000 if guesses else 0
                if seconds<60: crack=f"{seconds:.2f} seconds"
                elif seconds<3600: crack=f"{seconds/60:.1f} minutes"
                elif seconds<86400: crack=f"{seconds/3600:.1f} hours"
                elif seconds<31557600: crack=f"{seconds/86400:.1f} days"
                elif seconds<31557600*1e6: crack=f"{seconds/31557600:.1f} years"
                else: crack="Astronomically long (theoretical)"
                return self.send_json(200,{"strength":label,"entropy":entropy,"length":len(password),"pool_size":pool,"log10_guesses":round(math.log10(guesses),2) if guesses else 0,"crack_time":crack,"checks":{"length":len(password)>=8,"uppercase":any(c.isupper() for c in password),"lowercase":any(c.islower() for c in password),"digit":any(c.isdigit() for c in password),"symbol":any(not c.isalnum() for c in password)},"feedback":feedback,"sha256":sha256_fingerprint(password) if password else ""})
            if self.path=="/api/hash":
                algorithm=data.get("algorithm","scrypt")
                if not password:return self.send_json(400,{"error":"Enter a password first"})
                if algorithm=="scrypt":return self.send_json(200,{"hash":hash_password(password),"algorithm":"scrypt","bits":256})
                if algorithm=="sha256":return self.send_json(200,{"hash":sha256_fingerprint(password),"algorithm":"SHA-256","bits":256})
                return self.send_json(400,{"error":"Unsupported algorithm"})
            if self.path=="/api/verify":
                encoded=data.get("hash","")
                if not isinstance(encoded,str):return self.send_json(400,{"error":"Hash must be text"})
                return self.send_json(200,{"verified":verify_password(password,encoded)})
            if self.path=="/api/generate":return self.send_json(200,{"password":generate_password(data.get("length",20))})
            if not password:return self.send_json(400,{"error":"Enter a password first"})
            try:return self.send_json(200,check_breach(password))
            except (urllib.error.URLError,TimeoutError,OSError):return self.send_json(503,{"error":"Breach lookup is temporarily unavailable. Check your internet connection and try again."})
        except (ValueError,TypeError,json.JSONDecodeError) as exc:return self.send_json(400,{"error":str(exc)})
        except Exception:return self.send_json(500,{"error":"Unexpected server error"})

if __name__=="__main__":
    host,port="127.0.0.1",int(os.environ.get("CIPHERLAB_PORT","8080")); server=ThreadingHTTPServer((host,port),Handler)
    print(f"\nCipherLab is running at http://{host}:{port}\nLocal-only server. Press Ctrl+C to stop.\n")
    try:server.serve_forever()
    except KeyboardInterrupt:print("\nShutting down...")
    finally:server.server_close()
