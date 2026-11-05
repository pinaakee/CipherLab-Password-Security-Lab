# CipherLab — Password Security Lab

A local-first Python cybersecurity portfolio project for exploring password security.

## Features
- Password strength assessment and character-class checklist
- Theoretical entropy, search-space size and illustrative guessability estimate
- Local common-password dictionary check
- Have I Been Pwned Pwned Passwords lookup using the k-anonymity range API
- Cryptographically secure password generator (`secrets`)
- Salted scrypt password hashing and verification
- SHA-256 fingerprint demonstration (not for password storage)
- Downloadable JSON security report (excludes password and hashes)
- Responsive browser UI and command-line interface

## Run locally
Requires Python 3.10+; no third-party Python packages.

```bash
python app.py
```

Open **http://127.0.0.1:8080**. Stop with `Ctrl+C`. The app binds to localhost and is intended for learning, not production authentication. If port 8080 is occupied, change `port = 8080` near the bottom of `app.py`.

## Breach lookup privacy
CipherLab computes a SHA-1 digest locally, sends only its first five hexadecimal characters to the HIBP Pwned Passwords range endpoint, then compares returned suffixes locally. The plaintext password and full hash are not sent. Internet access is required. A no-match result is not a guarantee that a password has never been exposed.

## Analysis limitations
Entropy and crack-time values are estimates, not guarantees. Crack time uses an illustrative rate of 10 billion guesses/second and does not model attacker hardware, password reuse, targeted guessing, leaked personal information, or all pattern-based attacks.

## Security notes
- Use **scrypt** for password-storage demonstrations. SHA-256 is fast and shown only as a fingerprint example.
- Use a password manager to create and store unique passwords.
- Do not paste real passwords into screenshots, logs, source code, or public repositories.

## Tests
```bash
python -m unittest discover -s tests -v
```

## Tech stack
Python standard library (`http.server`, `hashlib`, `secrets`, `urllib`), HTML, CSS and vanilla JavaScript.

## Screenshots and demo GIF
Add real screenshots captured with sample-only passwords under `screenshots/` and a short screen recording under `demo/`. Do not publish real credentials or hashes.
