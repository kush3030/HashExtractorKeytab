# HashExtractorKeytab
A Python tool for parsing Kerberos keytab (`.keytab`) files and extracting cryptographic keys, including **RC4-HMAC (NTLM)**, **AES-128**, and **AES-256**.  
Optionally, it can attempt to **crack NTLM hashes** using Hashcat.

## 🚀 Features

- **Parse Keytab Files (`.keytab`)**: Extract principal names, timestamps, key versions, and encryption keys.
- **Extract NTLM Hashes**: Supports **RC4-HMAC (NTLM)** hash extraction for password cracking.
- **Crack NTLM Hashes**: (Optional) Uses **Hashcat (Mode 1000)** for NTLM password recovery.
- **Supports AES Keys**: Identifies **AES-128** and **AES-256** keys for further security analysis.

## 📦 Requirements

- Python 3.6 or later
- Hashcat (if using the `--crack` feature)
- Wordlist file (e.g., `rockyou.txt` for cracking)

## 🔧 Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/kush3030/HashExtractorKeytab.git
   cd HashExtractorKeytab
2. **Run the Script**
   ```bash
   python HashExtractorKeytab.py file.keytab
3. **Crack Extracted NTLM Hashes (Optional)**
   ```bash
   python HashExtractorKeytab.py file.keytab --crack --wordlist rockyou.txt
   
