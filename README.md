<div align="center">

```
 ██╗   ██╗ ██████╗ ████████╗    ██╗  ██╗███████╗██╗   ██╗    ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
 ██║   ██║██╔════╝ ╚══██╔══╝    ██║ ██╔╝██╔════╝╚██╗ ██╔╝    ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
██║   ██║██║  ███╗   ██║       █████╔╝ █████╗   ╚████╔╝     ██║   ██║███████║██║   ██║██║     ██║
╚██╗ ██╔╝██║   ██║   ██║       ██╔═██╗ ██╔══╝    ╚██╔╝      ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║
 ╚████╔╝ ╚██████╔╝   ██║       ██║  ██╗███████╗   ██║        ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║
  ╚═══╝   ╚═════╝    ╚═╝       ╚═╝  ╚═╝╚══════╝   ╚═╝         ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝
```

# VGT Key Vault
### AES-256-GCM Cryptographic API Key Manager for WordPress

[![License](https://img.shields.io/badge/License-AGPLv3-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.1.0-brightgreen?style=for-the-badge)](#)
[![PHP](https://img.shields.io/badge/PHP-8.0+-blue?style=for-the-badge&logo=php)](https://php.net)
[![WordPress](https://img.shields.io/badge/WordPress-6.0+-21759B?style=for-the-badge&logo=wordpress)](https://wordpress.org)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-gold?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-DIAMANT_VGT_SUPREME-purple?style=for-the-badge)](#)

**OMEGA PROTOCOL ACTIVE · AAD CONTEXT BINDING · ZERO PLAINTEXT STORAGE**

---

[![Donate via PayPal](https://img.shields.io/badge/☕_Support_the_Project-PayPal-00457C?style=for-the-badge&logo=paypal)](https://www.paypal.com/paypalme/dergoldenelotus)
[![VisionGaia Technology](https://img.shields.io/badge/🌍_VisionGaia-Technology-gold?style=for-the-badge)](https://visiongaiatechnology.de)

</div>

---

## ⚠️ DISCLAIMER: EXPERIMENTAL R&D PROJECT

This project is a **Proof of Concept (PoC)** and part of ongoing research and development at VisionGaia Technology. It is **not** a certified or production-ready product.

**Use at your own risk.** The software may contain security vulnerabilities, bugs, or unexpected behavior. It may break your environment if misconfigured or used improperly.

**Do not deploy in critical production environments** unless you have thoroughly audited the code and understand the implications. For enterprise-grade, verified protection, we recommend established and officially certified solutions.

Found a vulnerability or have an improvement? **Open an issue or contact us.**

---

## 📋 Changelog — V3.1.0

> **V3.1.0 is a comprehensive hardening upgrade.** Every change closes a concrete gap — no cosmetic version bumps.

| Area | V3.0.0 | V3.1.0 |
|---|---|---|
| **Exception Handling** | `\RuntimeException` | `VaultException` — typed, catchable separately |
| **Master Key Derivation** | `AUTH_SALT` + `SECURE_AUTH_KEY` only | All 8 WP salts + DB-generated fallback + `wp_hash()` anchor |
| **Registry Integrity** | No type checks | `is_array()` + `is_string()` guards — fatal-safe on DB corruption |
| **Admin HTTP Headers** | None | `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `X-XSS-Protection` |
| **Option Name Sanitizing** | `sanitize_text_field()` (too permissive) | `preg_replace('/[^a-zA-Z0-9_\-]/', '')` + enforced prefix namespace |
| **Error Feedback** | `saved`, `deleted`, `error_crypto` | + `error_input`, `error_delete` |
| **Internationalization** | None | Full `esc_html_e()` / `__()` / `esc_js()` coverage |
| **API Usage** | `get_key('vis_api_key_groq')` — full option name required | `get_key('groq_api_key')` — prefix added internally |
| **UI Display** | Shows full prefix (`vis_api_key_groq`) | Strips prefix — shows only identifier (`groq_api_key`) |

---

## 🔐 What is VGT Key Vault?

WordPress stores API keys in plaintext. Every plugin, every theme, every integration dumps credentials directly into `wp_options` — readable by anyone with database access.

**VGT Key Vault closes this gap.**

A cryptographic key management system that **seals every API key with AES-256-GCM + AAD Context Binding** before it ever touches the database. Even with full database access, an attacker retrieves nothing but cryptographically worthless ciphertext — **mathematically bound to the key identifier**.

Built as the cryptographic backbone of the **VisionGaiaTechnology Sentinel ecosystem** — and now available as a standalone open-source solution for any WordPress installation.

---

## ⚡ The Problem With Standard WordPress Key Storage

```
Standard WordPress Plugins:
  API Key entered         → stored as plaintext in wp_options
  DB dump by attacker     → all credentials compromised
  Plugin stores key_value → readable by any other plugin

VGT Key Vault:
  API Key entered         → AES-256-GCM encrypted with AAD
  DB dump by attacker     → ciphertext only → worthless
  Inter-plugin access     → one authenticated API call
```

---

## 🏛️ Architecture — Three Core Kernels

```
┌─────────────────────────────────────────────────────────────┐
│                    VGT KEY VAULT PROTOCOL                    │
├───────────────────┬───────────────────┬─────────────────────┤
│   CRYPTO KERNEL   │  REGISTRY KERNEL  │    ADMIN KERNEL     │
│                   │                   │                      │
│  AES-256-GCM      │  O(1) Hash Map    │  Glassmorphism UI   │
│  GCM Auth Tag     │  Auto-Migration   │  Key Injection Form │
│  AAD Binding      │  Auto-Heal        │  Vault Dashboard    │
│  HKDF + 8 Salts   │  Type Guards      │  Security Headers   │
│  Random IV        │  Index Registry   │  Delete with Nonce  │
│  wp_hash Anchor   │                   │  i18n Ready         │
└───────────────────┴───────────────────┴─────────────────────┘
```

---

## 🔑 The AAD Context Binding — What Makes This Different

Standard AES-256-GCM encrypts data. VGT Key Vault goes further with **AAD (Additional Authenticated Data)** — binding every ciphertext to its identifier:

```
WITHOUT AAD (standard encryption):
  encrypt("sk-groq-xxx") → Ciphertext_A
  Attacker copies Ciphertext_A to option "vis_api_key_other"
  decrypt(Ciphertext_A) → "sk-groq-xxx" ✓ (Ciphertext Swapping works)

WITH AAD (VGT Key Vault):
  encrypt("sk-groq-xxx", context="vis_api_key_groq") → Ciphertext_A
  Attacker copies Ciphertext_A to option "vis_api_key_other"
  decrypt(Ciphertext_A, context="vis_api_key_other") → FAIL ✗
  (GCM Authentication Tag mismatch — manipulation mathematically impossible)
```

**This eliminates an entire class of credential-swapping attacks** that most developers have never even heard of.

---

## 🔑 Crypto Kernel — `Crypto_Engine`

```php
// Master Key Derivation — HKDF-SHA256 over ALL 8 WordPress salts
// Fallback: DB-generated salt if constants missing
// Final anchor: wp_hash() — plugin never fails on hardened configs
hash_hkdf('sha256', $combined_salts, 0, 'vgt_vault_master_domain', $auth_salt);

// Encryption with AAD Context Binding
Crypto_Engine::encrypt($api_key, $option_name);

// Decryption — verified against AAD (tamper detection built-in)
// Throws VaultException on mismatch — catchable separately from generic errors
Crypto_Engine::decrypt($ciphertext, $option_name);
```

**Key Architecture (V3.1.0):**
- Master key derived via **HKDF-SHA256** from **all 8 WordPress salts** — never stored
- **DB-generated fallback salt** — plugin functions even when `wp-config.php` constants are absent or weak
- **`wp_hash()` anchor** — last-resort safety net on any hosting configuration
- Every encryption uses a **fresh random IV** (`random_bytes`)
- **GCM Authentication Tag** appended — detects any modification
- **AAD Context ID** binds ciphertext to its exact storage location
- Typed **`VaultException`** — catchable independently of generic `\Exception` handlers

---

## 📦 Registry Kernel — `Vault_Registry`

```
O(1) Hash Map instead of O(n) Array scan:

  [ "vis_api_key_groq"   => true ]   ← isset() lookup: O(1)
  [ "vis_api_key_openai" => true ]
  [ "vis_api_key_stripe" => true ]

Type Guards (V3.1.0):
  is_array() check before iteration   — fatal-safe on DB corruption
  is_string() check on each entry     — no PHP warnings on malformed data

Auto-Migration: Old array format detected → silently upgraded
Auto-Heal:      Option missing from DB → removed from index automatically
```

---

## 🛡️ Admin Kernel — `Admin_Dashboard`

```
┌──────────────────────────────────────────────────────┐
│  VGT Crypto Vault                                    │
│  AES-256-GCM · Context-Aware AAD Binding             │
├──────────────────────┬───────────────────────────────┤
│  Key Injection       │  Active Cryptonodes (O(1))    │
│                      │                               │
│  Identifier          │  groq_api_key        [Term.]  │
│  [groq_api_key]      │  Hash: K7mX9pQr2nZ...         │
│                      │                               │
│  Plaintext Token     │  openai_api_key      [Term.]  │
│  [sk-...]            │  Hash: Lp4vN8kJhFm...         │
│                      │                               │
│  [In Vault versiegeln]│                              │
└──────────────────────┴───────────────────────────────┘
```

**V3.1.0 Admin Hardening:**
- **Security Headers injected** on every admin page render: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-XSS-Protection: 0`
- **Strict option name sanitization:** `preg_replace('/[^a-zA-Z0-9_\-]/', '')` — special characters and injection attempts rejected at input
- **Enforced prefix namespace:** all keys stored under `vis_api_key_` internally — cross-namespace overwrites structurally impossible
- **UI strips prefix:** dashboard displays `groq_api_key`, not `vis_api_key_groq` — cleaner, less error-prone
- **Extended error codes:** `error_input` (invalid identifier) and `error_delete` (deletion failed) in addition to `error_crypto`
- **Full i18n coverage:** all output via `esc_html_e()` / `__()` / `esc_js()` — translation-ready, XSS-safe
- **Nonce verification** on all POST requests
- **`manage_options` capability** check before any operation
- **Confirmation dialog** before key termination

---

## 🔌 Inter-Plugin API — One Line Access

V3.1.0 simplifies the API. Pass only the identifier — the prefix is handled internally.

```php
use VGT\Vault\API;

// V3.0.0 (deprecated pattern — full option name required)
$api_key = API::get_key('vis_api_key_groq');

// V3.1.0 (current — identifier only, prefix added internally)
$api_key = API::get_key('groq_api_key');

// VaultException — typed, catchable separately
try {
    $key = API::get_key('stripe_api_key');
} catch (\VGT\Vault\VaultException $e) {
    // Key missing, tampered, or decryption failed
}
```

**No plaintext ever stored. No raw option access. One secure interface.**

---

## 🚀 Installation

### Requirements

```
PHP:        8.0+
WordPress:  6.0+
OpenSSL:    enabled (standard on all hosting)
```

### Setup in 3 Steps

**1. Upload & Activate:**
```
WordPress Admin → Plugins → Upload Plugin → ZIP → Install → Activate
```

**2. Store your first API key:**
```
WordPress Admin → VGT Vault → Key Injection
Identifier:      groq_api_key
Plaintext Token: sk-your-key-here
→ [In Vault versiegeln]
```

**3. Use in your plugin:**
```php
$key = \VGT\Vault\API::get_key('groq_api_key');
```

---

## 📊 Security Comparison

| Feature | Standard `wp_options` | VGT Key Vault |
|---|---|---|
| Database encryption | ❌ Plaintext | ✅ AES-256-GCM |
| Ciphertext Swapping protection | ❌ | ✅ AAD Context Binding |
| Key derivation | ❌ Raw storage | ✅ HKDF-SHA256 over all 8 WP salts |
| Fallback on missing salts | ❌ Fatal / empty key | ✅ DB salt + `wp_hash()` anchor |
| Tamper detection | ❌ | ✅ GCM Auth Tag |
| O(1) Registry lookup | ❌ | ✅ Hash Map |
| CSRF protection | ❌ | ✅ `wp_verify_nonce` |
| Option name injection prevention | ❌ | ✅ Strict regex + prefix namespace |
| Admin clickjacking protection | ❌ | ✅ `X-Frame-Options: DENY` |
| MIME sniffing protection | ❌ | ✅ `X-Content-Type-Options: nosniff` |
| Typed exception handling | ❌ | ✅ `VaultException` |
| Registry fatal-safety | ❌ | ✅ Type guards on DB read |
| Inter-plugin API | ❌ | ✅ Typed facade, prefix-transparent |
| i18n / translation ready | ❌ | ✅ Full `__()` / `esc_html_e()` coverage |
| DB dump resistance | ❌ Full compromise | ✅ Ciphertext only |

---

## 📁 File Structure

```
vgt-key-vault/
├── vgt-key-vault.php          ← single-file plugin
│
└── Inline Kernels:
    ├── Crypto_Engine          ← AES-256-GCM + AAD + HKDF (8 salts + fallback)
    ├── Vault_Registry         ← O(1) Hash Map + Type Guards + Auto-Migration
    ├── Admin_Dashboard        ← UI + Security Headers + i18n + nonce handlers
    ├── VaultException         ← Typed exception class
    └── API                    ← inter-plugin facade (prefix-transparent)
```

**No external dependencies. No composer. No build step.**
One PHP file. Drop it in and it works.

---

## ⚠️ Important Security Notice

```
⚠️  VGT Key Vault derives its master key from all 8 WordPress salts.

    If you change any salt constant in wp-config.php,
    ALL stored ciphertexts become permanently unreadable.

    Before migration or salt rotation:
    1. Decrypt and export all keys from the Vault Dashboard
    2. Rotate salts in wp-config.php
    3. Re-import keys into the new Vault instance

    Note: If wp-config.php constants are absent or empty,
    V3.1.0 automatically falls back to a DB-stored salt and wp_hash().
    The plugin will not crash on hardened or non-standard configurations.
```

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first.

```bash
git clone https://github.com/VisionGaiaTechnology/wpkeyvault
cd vgt-key-vault
```

**Found a vulnerability?**
Report via the **VGT Sentinel Operative Registry** — responsible disclosure is rewarded.

---

## ☕ Support the Project

VGT Key Vault is free and open-source under AGPLv3.
If it saved you time, money, or a security incident — consider supporting:

<div align="center">

[![Donate via PayPal](https://img.shields.io/badge/☕_Buy_us_a_coffee-PayPal-00457C?style=for-the-badge&logo=paypal)](https://www.paypal.com/paypalme/dergoldenelotus)

</div>

---

## 📄 License

**AGPLv3 License** · © 2026 VisionGaia Technology · Cologne, Germany

Anyone using and modifying this plugin must publish changes under AGPLv3.
Commercial use permitted. Attribution required.

---

<div align="center">

**Built as part of the VisionGaiaTechnology Security Ecosystem**

[![VisionGaia Technology](https://img.shields.io/badge/🌍_Visit-VisionGaia_Technology-gold?style=for-the-badge)](https://visiongaiatechnology.de)
[![Sentinel](https://img.shields.io/badge/🛡️_Powered_by-VGT_Sentinel-purple?style=for-the-badge)](#)

```
No plaintext. No compromise. No exceptions.
```

*VISIONGAIATECHNOLOGY – WE ARCHITECT THE FUTURE OF SECURITY.*

</div>
