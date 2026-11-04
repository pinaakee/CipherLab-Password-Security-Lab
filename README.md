# Password Security Tool

A small Python portfolio project combining:
- Password strength estimation
- Local common-password dictionary checks
- Secure salted password hashing with **scrypt**
- Password hash verification
- Optional SHA-256 fingerprint demonstration

## Requirements

- Python 3.10 or newer
- No third-party packages required

## Run the web UI (recommended)

```bash
python app.py
```

Open **http://127.0.0.1:8000** in your browser. The UI is inspired by a dark
cryptographic dashboard and includes live strength checks, a hash visualization,
scrypt/SHA-256 selection, hash copying, and scrypt verification. Stop the local
server with `Ctrl+C`.

The web server binds to `127.0.0.1` (your own computer) by default. It is a
learning/portfolio app, not a production authentication service.

## Run the command-line version

```bash
python password_tool.py
```

Choose an option from the menu. Password input is hidden while typing.

To use your own local wordlist:

```bash
python password_tool.py --wordlist /path/to/passwords.txt
```

The included `data/common_passwords.txt` is intentionally small so the project
works immediately. For a larger local list, download a curated list from a
trusted source such as the SecLists repository and point `--wordlist` to it.
Check the list's licence and keep large leaked-password datasets local.

## Security notes

- **Use scrypt for password storage.** It is salted and deliberately expensive
  compared with a fast general-purpose hash. Store the complete encoded string
  returned by option 2, then verify with option 3.
- **SHA-256 is not a password-storage algorithm.** Option 4 is included only to
  demonstrate hashing and should not be used to store login credentials.
- The strength score is a basic heuristic, not a guarantee. It does not know
  whether a password has been reused elsewhere or appears in a large breach
  corpus. A password manager-generated, unique passphrase is usually a better
  choice than trying to satisfy arbitrary complexity rules.
- The local wordlist check is exact-match only. It does not detect variations
  such as `P@ssw0rd!`.
- Do not paste real passwords into screenshots, logs, source code, or public
  repositories. Never commit actual user passwords or production hashes.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Suggested portfolio improvements

1. Add a Have I Been Pwned range-API lookup using its k-anonymity model (send
   only the first five hexadecimal characters of a SHA-1 digest; never send
   the plaintext password).
2. Add a GUI or web interface while keeping password handling server-side.
3. Add more tests and document the benchmarked scrypt parameters for your
   deployment environment.


## UI stack

- Frontend: HTML, CSS, vanilla JavaScript
- Backend: Python standard library `http.server`
- Password hashing: Python `hashlib.scrypt`
- No third-party Python dependencies
