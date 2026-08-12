<div align="center">

```
 _____ ___ _____ ____    ____                     _
|_   _/ _ \_   _|  _ \  |  _ \  ___  ___ ___   __| | ___ _ __
  | || | | || | | |_) | | | | |/ _ \/ __/ _ \ / _` |/ _ \ '__|
  | || |_| || | |  __/  | |_| |  __/ (_| (_) | (_| |  __/ |
  |_| \___/ |_| |_|     |____/ \___|\___\___/ \__,_|\___|_|
```

### `>> offline RFC-6238 engine // zero network calls`

[![Made with Python](https://img.shields.io/badge/made%20with-python-39FF14?style=for-the-badge&logo=python&logoColor=black)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-00FFFF?style=for-the-badge)](./LICENSE)
[![Offline First](https://img.shields.io/badge/network%20calls-ZERO-FF00FF?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/status-online-39FF14?style=for-the-badge)](#)

**[github.com/realnishil/TOTP-Decoder-by-nish](https://github.com/realnishil/TOTP-Decoder-by-nish)**
crafted by [`@notnishil`](https://github.com/realnishil)

</div>

---

```diff
+ [+] secret accepted. deriving shared key material...
+ [+] starting local clock sync check...
+ [+] engine online. computing codes every 30s, fully offline.
```

## `// WHAT IS THIS`

A **fully offline, from-scratch TOTP (Time-based One-Time Password) engine**, implementing **RFC 6238** on top of **HOTP (RFC 4226)** with nothing but Python's standard library — no `pyotp`, no third-party crypto, no network calls, ever.

It doesn't just spit out a 6-digit code — it shows you **exactly how it gets there**: the time-step counter, the raw HMAC-SHA1 digest, the dynamic truncation offset, and the final modulo — all rendered live in a neon terminal UI with a countdown bar.

> Same math your authenticator app runs. Fully transparent, fully local.

---

## `// FEATURES`

| | |
|---|---|
| 🔐 | **RFC 6238 / RFC 4226 compliant** — real HOTP → TOTP derivation, byte for byte |
| 🌐 | **Zero network calls** — everything computed locally from your Base32 secret |
| 🧬 | **Verbose crypto breakdown** — see the counter bytes, HMAC digest, truncation offset & masked int |
| 🎨 | **Hacker-green live terminal UI** — colorized output with a real-time expiry bar |
| ⏱️ | **Live-refreshing codes** — auto-updates every 30s, just like your phone's authenticator |
| 🧪 | **Demo mode** — no secret? it drops in a working demo key so you can try it instantly |

---

## `// HOW IT WORKS`

```
┌─────────────┐    ┌──────────────────┐    ┌────────────────────┐    ┌───────────────┐
│  T0 → time   │ →  │  HMAC-SHA1(K, C)  │ →  │  dynamic truncation │ →  │  mod 10^digits │
│  step counter│    │   20-byte digest  │    │   4-byte slice      │    │   6-digit OTP  │
└─────────────┘    └──────────────────┘    └────────────────────┘    └───────────────┘
```

1. **Counter derivation** — `T = floor((unix_time - T0) / step)`, packed into 8 big-endian bytes
2. **HMAC-SHA1** — the Base32-decoded secret keys an HMAC over the counter bytes
3. **Dynamic truncation** — last nibble of the digest picks a 4-byte offset, masked to 31 bits
4. **Final code** — that integer, mod `10^digits`, zero-padded

Every one of these steps is printed live the first time you run it.

---

## `// USAGE`

```bash
$ git clone https://github.com/realnishil/TOTP-Decoder-by-nish.git
$ cd TOTP-Decoder-by-nish
$ python3 totp_hacker_claude.py
```

You'll be prompted for a **Base32 secret** (the same one your 2FA setup QR code encodes). Leave it blank to run a demo key instead.

```
[?] enter base32 secret key (from your QR setup): JBSWY3DPEHPK3PXP

CODE: 482 913   expires in 21s  ████████████████████░░░░░░░░░░
```

Press `Ctrl+C` to exit the live loop at any time.

---

## `// DISCLAIMER`

This tool is for **educational use and managing your own accounts** — decoding TOTP secrets you already own (e.g. exported from your own 2FA setup). It does not attack, brute-force, or intercept anyone else's credentials.

---

<div align="center">

### `// LICENSE`

Released under the **Apache License 2.0** — see [`LICENSE`](./LICENSE) in this repo for full terms.

---

<sub>built offline, stays offline 🔒</sub>

**[`@notnishil`](https://github.com/realnishil)** · [TOTP-Decoder-by-nish ↗](https://github.com/realnishil/TOTP-Decoder-by-nish.git)

</div>
