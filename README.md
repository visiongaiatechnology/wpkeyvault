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

This project is a **Proof of Concept (PoC)** Wordpress Security Layer. It is **not** a Enterprise Plugin, and can be unsafe.

**Do not use this in critical production environments.** For enterprise-grade Key protection, we recommend established Solutions.


## 🔐 What is VGT Key Vault?

WordPress stores API keys in plaintext. Every plugin, every theme, every integration dumps credentials directly into `wp_options` — readable by anyone with database access.

**VGT Key Vault closes this gap.**

A cryptographic key management system that **seals every API key with AES-256-GCM + AAD Context Binding** before it ever touches the database. Even with full database access, an attacker retrieves nothing but cryptographically worthless ciphertext — **mathematically bound to the key identifier**.

Built as the cryptographic backbone of the **VisionGaiaTechnology Sentinel ecosystem** — and now available as a standalone open-source solution for any WordPress installation.

---

<img width="1158" height="515" alt="{F8E458D8-9F16-4260-A914-6B825267D9B8}" src="https://github.com/user-attachments/assets/5703444b-1efb-46cd-abd3-c131d1ee6d88" />



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
│  HKDF Key Derive  │  Index Registry   │  Delete with Nonce  │
│  Random IV        │                   │  Status Alerts      │
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
// Master Key Derivation via HKDF (not raw salt — proper key derivation)
hash_hkdf('sha256', SECURE_AUTH_KEY, 0, 'vgt_vault_master_domain', AUTH_SALT);

// Encryption with AAD Context Binding
Crypto_Engine::encrypt($api_key, $option_name);

// Decryption — verified against AAD (tamper detection built-in)
Crypto_Engine::decrypt($ciphertext, $option_name);
```

**Key Architecture:**
- Master key derived via **HKDF-SHA256** from WordPress salts — never stored
- Every encryption uses a **fresh random IV** (`random_bytes`)
- **GCM Authentication Tag** appended — detects any modification
- **AAD Context ID** binds ciphertext to its exact storage location

---

## 📦 Registry Kernel — `Vault_Registry`

```
O(1) Hash Map instead of O(n) Array scan:

  [ "vis_api_key_groq" => true ]   ← isset() lookup: O(1)
  [ "vis_api_key_openai" => true ]
  [ "vis_api_key_stripe" => true ]

Auto-Migration: Old array format detected → silently upgraded
Auto-Heal: Option missing from DB → removed from index automatically
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
│  System Identifier   │  vis_api_key_groq    [Term.]  │
│  [vis_api_key_...]   │  Hash: K7mX9pQr2nZ...         │
│                      │                               │
│  Plaintext Token     │  vis_api_key_openai  [Term.]  │
│  [sk-...]            │  Hash: Lp4vN8kJhFm...         │
│                      │                               │
│  [In Vault versiegeln]│                              │
└──────────────────────┴───────────────────────────────┘
```

Every action is protected:
- **Nonce verification** on all POST requests
- **`manage_options` capability** check before any operation
- **Confirmation dialog** before key termination

---

## 🔌 Inter-Plugin API — One Line Access

Other plugins in your ecosystem retrieve keys with a single authenticated call:

```php
use VGT\Vault\API;

// O(1) retrieval + AES-256-GCM decryption in one call
$api_key = API::get_key('vis_api_key_groq');

// Throws RuntimeException if key missing or tampered
try {
    $key = API::get_key('vis_api_key_stripe');
} catch (\RuntimeException $e) {
    // Handle missing/compromised key
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
System Identifier: vis_api_key_groq
Plaintext Token:   sk-your-key-here
→ [In Vault versiegeln]
```

**3. Use in your plugin:**
```php
$key = \VGT\Vault\API::get_key('vis_api_key_groq');
```

---

## 📊 Security Comparison

| Feature | Standard `wp_options` | VGT Key Vault |
|---|---|---|
| Database encryption | ❌ Plaintext | ✅ AES-256-GCM |
| Ciphertext Swapping protection | ❌ | ✅ AAD Context Binding |
| Key derivation | ❌ Raw storage | ✅ HKDF-SHA256 |
| Tamper detection | ❌ | ✅ GCM Auth Tag |
| O(1) Registry lookup | ❌ | ✅ Hash Map |
| CSRF protection | ❌ | ✅ wp_verify_nonce |
| Inter-plugin API | ❌ | ✅ Typed facade |
| Auto-Heal registry | ❌ | ✅ |
| DB dump resistance | ❌ Full compromise | ✅ Ciphertext only |

---

## 📁 File Structure

```
vgt-key-vault/
├── vgt-key-vault.php          ← single-file plugin
│
└── Inline Kernels:
    ├── Crypto_Engine          ← AES-256-GCM + AAD + HKDF
    ├── Vault_Registry         ← O(1) Hash Map + Auto-Migration
    ├── Admin_Dashboard        ← UI + nonce-protected handlers
    └── API                    ← inter-plugin facade
```

**No external dependencies. No composer. No build step.**  
One PHP file. Drop it in and it works.

---

## ⚠️ Important Security Notice

```
⚠️  VGT Key Vault derives its master key from WordPress salts.

    If you change AUTH_SALT or SECURE_AUTH_KEY in wp-config.php,
    ALL stored ciphertexts become permanently unreadable.

    Before migration or salt rotation:
    1. Decrypt and export all keys from the Vault Dashboard
    2. Rotate salts
    3. Re-import keys into the new Vault
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

</div
