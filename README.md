# 🔒 SecureCloud — Enterprise Secure Cloud File Sharing Cryptosystem

> **Department of Computer Science and Engineering**  
> **KLE Technological University, Hubballi**  
> **Course:** Cryptography and Network Security (26ECSC403)  
> **Faculty / Guide:** Prof. Roopa Badami  
> **Review Stage:** Review 1 — Problem Statement, Requirement Analysis & Preliminary System Prototype  

---

## 👥 Project Team & Responsibility Matrix (Slide 1 & Slide 8)

| Team Member | USN | Project Role & Assigned Ownership |
|:---|:---|:---|
| **Abhinandan N M** | `01FE23BCS079` | **System Design & Security Architecture** (Key hierarchy, threat modeling, protocol design) |
| **Sushant Maheshwari** | `01FE23BCS075` | **Backend & File Security** (AES-256-CBC engine, SHA-256 integrity, PBKDF2 KEK wrapping) |
| **Aditya Kadwadkar** | `01FE23BCS152` | **Frontend, Integration & Validation** (Security UI, live SIEM audit, tamper simulation lab) |

---

## 📋 1. Problem Identification & Statement (Slide 2)

### The Core Problem
In standard cloud storage and networked file transfer services, content protection (confidentiality & integrity) and access control (authentication & authorization) are **rarely enforced together cryptographically**. Files are typically stored in plaintext on disk, leaving data vulnerable to:
1. **Unauthorized Access:** Rogue cloud administrators, compromised credentials, or perimeter breaches.
2. **Data Exposure:** Plaintext data leaks when underlying storage buckets or database snapshots are exposed.
3. **File Modification (Tampering):** Silent malware or adversary bit flips altering confidential files undetected.
4. **Uncontrolled Sharing:** Inability to revoke access once a link or file is shared.

### Formal Problem Statement
> *"Files shared through cloud-based systems can be accessed, intercepted, or modified by unauthorized parties unless authentication, access control, confidentiality, integrity, and secure communication are enforced together. This system guarantees end-to-end cryptographic protection at rest and in transit."*

---

## 🎯 2. Objectives & Cryptographic Enforcement (Slide 3)

| ID | Identified Risk | Engineering Objective | Exact Cryptographic Implementation in Code |
|:---|:---|:---|:---|
| **O1** | Unauthorized Access | Authenticated access for registered users only | **bcrypt (Cost 12)** password hashing + stateless **JWT (HMAC-SHA256)** 24h bearer tokens (`app/auth.py`) |
| **O2** | File Exposure | Keep stored file content unreadable without decryption | **AES-256-CBC** with random 256-bit DEK per file, wrapped by Master KEK via **PBKDF2-HMAC-SHA256** (`app/crypto_utils.py`) |
| **O3** | Unauthorized Modification | Provide integrity protection to detect file tampering | Pre-storage **SHA-256 cryptographic digest** verified on every download before decryption (`app/files.py`) |
| **O4** | Insecure Communication | Protect data during transmission client ↔ server | **HTTPS / TLS 1.3** transport security (`run.py` with PyOpenSSL adhoc context) |
| **O5** | Uncontrolled Sharing | Permission-based sharing with revocable access | Granular access control (`read`/`write`), optional ISO expiration timestamp, and **instant revocation** (`app/shares.py`) |

---

## 🛡️ 3. Threat Model & Assets Analysis (Slide 5)

```
       [ UNAUTHORIZED USER / ATTACKER ]
                      │
     ┌────────────────┼────────────────┐
     ▼                ▼                ▼
[Interception]  [Data Exposure]  [File Tampering]
   In Transit      At Rest           On Disk
     │                │                │
     ▼                ▼                ▼
 [TLS 1.3 /      [AES-256-CBC     [SHA-256 Hash
   HTTPS]          DEK + KEK]       Verification]
```

### Assets Protected:
- **Payload Files:** Stored exclusively as AES-256-CBC ciphertext chunks in `uploads/<uuid>`.
- **User Credentials:** Stored as salted, adaptive Blowfish hashes using bcrypt (cost 12).
- **Cryptographic Keys:** File-level Data Encryption Keys (DEKs) are never stored in plaintext; they are wrapped with the Master KEK.
- **Access Permissions:** Maintained in relational schemas with timestamped expiry and revocation flags.

---

## 🏛️ 4. Layered System Architecture (Slide 6)

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CLIENT TIER (HTML5 / CSS3 / ES6)                     │
│  - Encrypted Vault Dashboard    - Live Security SIEM Audit Trail      │
│  - Cryptographic Inspector      - Live Tamper Simulation Lab (O3)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTPS (TLS 1.3)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 API SECURITY GATEWAY (Flask Application)               │
│                                                                        │
│  ┌───────────────────────┐  ┌──────────────────────────────────────┐  │
│  │ Auth & Access Control │  │        File Management Engine        │  │
│  │  - bcrypt-12 Hashing  │  │  - Multipart Stream Processing       │  │
│  │  - JWT Bearer Guard   │  │  - Ownership & Delegation RBAC       │  │
│  └───────────────────────┘  └──────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                CRYPTOGRAPHIC ENGINE (pycryptodome)              │  │
│  │  - KDF: PBKDF2-HMAC-SHA256 (100,000 rounds) -> Master KEK       │  │
│  │  - Cipher: AES-256-CBC (256b DEK + 128b IV) with PKCS#7        │  │
│  │  - Integrity: SHA-256 FIPS 180-4 Pre- & Post-Storage Hash      │  │
│  │  - Key Wrapping: AES-256-ECB DEK Encapsulation                  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          STORAGE & PERSISTENCE                         │
│  - SQLite Database (`secure_cloud.db`): Metadata, Hashes, Wrapped DEKs │
│  - Disk Storage (`uploads/<uuid>`): Raw Unreadable Ciphertext Chunks   │
│  - Immutable Security Audit Log Table (`security_audit_logs`)          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 5. System Workflows (Slide 7)

### Workflow 1: Secure File Upload (Confidentiality + Integrity)
```
[Client Plaintext]
       │
       ├──────────────────────────────────────────┐
       │ (1) SHA-256                              │ (2) Generate DEK (32B) & IV (16B)
       ▼                                          ▼
[Stored file_hash]                   [AES-256-CBC Payload Encrypt]
                                                  │
                                                  ├───────────────┐
                                                  ▼               ▼
                                            [Ciphertext]     [Wrap DEK with KEK]
                                                  │               │
                                                  ▼               ▼
                                           [uploads/<uuid>]  [DB: encrypted_key]
```

### Workflow 2: Secure Download (Authorization + Tamper Verification)
```
[Client Request GET /api/files/<id>/download]
       │
       ▼
[Verify JWT Token] ──(Invalid)──> [HTTP 401 Unauthorized]
       │ (Valid)
       ▼
[Check Access: Is Owner OR Has Non-Revoked Active Share?] ──(No)──> [HTTP 403 Forbidden]
       │ (Yes)
       ▼
[Unwrap DEK using Master KEK (PBKDF2)]
       │
       ▼
[Decrypt Ciphertext chunk via AES-256-CBC + PKCS#7 Unpad]
       │
       ▼
[Compute SHA-256(Decrypted_Plaintext)] == stored file_hash?
       ├── NO (TAMPER DETECTED!) ──> [ABORT DOWNLOAD! Log Security Alert! Return HTTP 409]
       └── YES (INTEGRITY PASS!)  ──> [Stream Original File as Download attachment]
```

### Workflow 3: Granular Sharing & Revocation (Objective O5)
```
[Owner] ──> Select Recipient & Set Permission (read/write) & Expiry ──> [DB: file_shares]
                                                                              │
                                                                   [Owner clicks Revoke]
                                                                              │
                                                                              ▼
                                                                     [revoked = True]
                                                                              │
                                                         [Subsequent access blocked: 403]
```

---

## 🧪 6. Live Academic Demonstration Guide for Faculty Review

During your review with **Prof. Roopa Badami**, demonstrate the system in this order:

### Step 1: Authentication & Token Security (Objective O1)
1. Open `https://localhost:5000` in Chrome (click *Advanced* → *Proceed to localhost*).
2. Register a user (e.g., `Abhinandan`, `Sushant`, `Aditya`).
3. Point out that the password is never stored directly—it is hashed using **bcrypt with cost factor 12**.
4. Log in and show that the session uses an **HMAC-SHA256 signed JWT bearer token**.

### Step 2: File Confidentiality & Key Hierarchy (Objective O2)
1. In the **Encrypted Vault**, drag and drop any file (e.g., a `.txt`, `.pdf`, or `.png`).
2. Point to the live upload progress steps:
   - Step 1: Plaintext SHA-256 digest computation
   - Step 2: Random 256-bit DEK generation & Master KEK wrap
   - Step 3: AES-256-CBC payload encryption
   - Step 4: Storage in `uploads/` under an unguessable UUID
3. Click the **Inspect Crypto (magnifying glass)** icon on the file row:
   - Show the **Wireshark-style Hex Dump** of the raw ciphertext.
   - Show the **Initialisation Vector (IV)** in hex.
   - Show the **Wrapped DEK** (encrypted with the Master Key).
   - Show the file in `uploads/` in Windows Explorer—it is completely unreadable ciphertext!

### Step 3: Live Tamper Detection & Integrity Proof (Objective O3)
1. In the Cryptographic Inspector modal, click **"Verify Integrity Now"**:
   - The system performs a live SHA-256 check and returns a green **"INTEGRITY VERIFIED"** badge.
2. Now click **"Simulate 1-Byte Tamper"**:
   - The system injects a single flipped bit into the ciphertext stored on disk, simulating a server-side attacker or bit rot.
   - Notice the status changes to **⚠️ TAMPERED**.
3. Now attempt to download the file by clicking **"Download & Verify"**:
   - The system intercepts the corrupted payload, detects the SHA-256 mismatch, halts the download, and displays a prominent **"CRITICAL SECURITY ALERT: Integrity Check Failed!"** warning.
4. Click **"Restore Original Ciphertext"** to demonstrate recovery.

### Step 4: Granular Sharing & Instant Revocation (Objective O5)
1. Click the **Share (users icon)** button next to any file.
2. Grant `read` access to another registered username.
3. Switch to that user's account and show that they can decrypt and download the file from **"Shared With Me"**.
4. Log back in as the owner and click **"Revoke"**.
5. Switch back to the recipient and attempt to download—the request is blocked immediately with an **HTTP 403 Access Denied** response!

### Step 5: Live Security Audit Trail (SIEM)
1. Click **"Security Audit Trail"** in the sidebar.
2. Show the real-time immutable event log displaying every registration, login, encryption, share, tamper simulation, and integrity verification with millisecond timestamps and IP addresses.

---

## 🚀 7. Quick Setup & Run Instructions

### Prerequisites
- Python 3.10+
- Modern Web Browser (Chrome / Edge / Firefox)

### Start the Application:
```powershell
# Open terminal in project root:
cd "C:\Users\Abhinandan\OneDrive\Desktop\CNS"

# Activate virtual environment:
.\venv\Scripts\activate

# Run the Secure HTTPS Server:
python run.py
```

### Access URL:
- **Secure Web UI:** [https://localhost:5000](https://localhost:5000)
- *Note:* Chrome will show an SSL warning because development uses a self-signed certificate. Click **Advanced → Proceed to localhost (unsafe)** to open the application.
