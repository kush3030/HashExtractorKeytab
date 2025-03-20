#!/usr/bin/env python3
import struct
import argparse
import sys
import subprocess
import tempfile
import os

def parse_keytab(file_data):
    """Parses the entire keytab file (version 0x502), returning a list of entries."""
    pos = 0
    # 1) Read the keytab file format version (2 bytes, big-endian)
    version = struct.unpack(">H", file_data[pos:pos+2])[0]
    pos += 2
    if version != 0x502:
        print(f"[!] Unsupported keytab version: 0x{version:04X}. Only 0x502 is supported.")
        sys.exit(1)

    entries = []
    # 2) Read until we exhaust the file_data
    while pos < len(file_data):
        if pos + 4 > len(file_data):
            break  # Not enough bytes to read entry size
        # Each entry starts with a 4-byte signed integer for the entry size
        entry_size = struct.unpack(">i", file_data[pos:pos+4])[0]
        pos += 4
        # The size may be negative; if so, take its absolute value
        entry_size = abs(entry_size)

        entry_data = file_data[pos:pos+entry_size]
        pos += entry_size

        # Parse this single entry
        entry = parse_entry(entry_data)
        entries.append(entry)

    return entries

def parse_entry(data):
    """
    Parses a single keytab entry according to MIT Kerberos 0x502 spec:
      1) 2 bytes: num_components (signed)
      2) 2 bytes: realm length, followed by realm
      3) For each principal component: 2 bytes length + component data
      4) If num_components was negative, read 4 bytes for name_type
      5) 4 bytes: timestamp
      6) 1 byte: key_vno_8 (the 'short' key version)
      7) Possibly 4 bytes: extended key_vno_32 (if leftover data remains)
      8) 2 bytes: key_type
      9) 2 bytes: key_length
      10) key_length bytes: key
    """
    pos = 0

    # (1) number of principal components (signed short)
    num_components = struct.unpack(">h", data[pos:pos+2])[0]
    pos += 2

    has_name_type = False
    if num_components < 0:
        has_name_type = True
        num_components = -num_components

    # (2) realm: length + string
    realm_len = struct.unpack(">h", data[pos:pos+2])[0]
    pos += 2
    realm = data[pos:pos+realm_len].decode(errors="replace")
    pos += realm_len

    # (3) principal components
    components = []
    for _ in range(num_components):
        comp_len = struct.unpack(">h", data[pos:pos+2])[0]
        pos += 2
        comp = data[pos:pos+comp_len].decode(errors="replace")
        pos += comp_len
        components.append(comp)

    # (4) optional name_type if original num_components was negative
    if has_name_type:
        # read 4 bytes (but we don't necessarily use it)
        _name_type = struct.unpack(">I", data[pos:pos+4])[0]
        pos += 4

    # (5) 4 bytes: timestamp
    timestamp = struct.unpack(">I", data[pos:pos+4])[0]
    pos += 4

    # (6) 1 byte: key_vno_8
    key_vno_8 = data[pos]
    pos += 1

    # Some keytabs have a 4-byte extended key_vno after the 1-byte version,
    # but ONLY if there's still enough data left before we reach the key_type.
    # We'll peek ahead to see if there's >= 8 bytes left (2 for key_type, 2 for key_len, plus some key data).
    extended_vno_32 = None

    # We'll check how many bytes remain:
    remaining = len(data) - pos
    # If there's at least 8 bytes left after reading the key_vno_8, then we might have a 4-byte extended vno
    # plus 2 bytes key_type, 2 bytes key_len, and >=1 byte of key data. We'll do a minimal check of 8 bytes
    # to see if extended vno is present.
    if remaining >= 8:
        # We'll read the next 4 bytes, but not consume them yet
        possible_extended_vno = struct.unpack(">I", data[pos:pos+4])[0]
        # Heuristic: If the next 2 bytes (after those 4) look like a valid key_type (like 17,18,23, etc.)
        # we might guess there's an extended vno. We'll do a safer approach: we'll parse as if we read it,
        # then see if the next field is a recognized key_type or not.
        test_pos = pos + 4
        test_key_type = struct.unpack(">h", data[test_pos:test_pos+2])[0]
        # If test_key_type is a known Kerberos type (17,18,23, etc.) or less than e.g. 1000, it's likely valid.
        # We'll check if 0 < test_key_type < 1000 as a heuristic.
        if 0 < test_key_type < 1000:
            # We'll assume we found an extended vno
            extended_vno_32 = possible_extended_vno
            pos += 4  # consume the 4 bytes
        # else we skip reading extended vno

    # If extended_vno_32 is present, it overrides the 1-byte key_vno_8
    if extended_vno_32 is not None:
        key_vno = extended_vno_32
    else:
        key_vno = key_vno_8

    # (7) 2 bytes: key_type
    key_type = struct.unpack(">h", data[pos:pos+2])[0]
    pos += 2

    # (8) 2 bytes: key_length
    key_length = struct.unpack(">h", data[pos:pos+2])[0]
    pos += 2

    # (9) key_length bytes: key
    key = data[pos:pos+key_length]
    pos += key_length

    principal = "/".join(components) + "@" + realm

    return {
        "principal": principal,
        "timestamp": timestamp,
        "key_vno": key_vno,
        "key_type": key_type,
        "key": key
    }

def run_hashcat(hash_file, wordlist):
    """Runs Hashcat (mode 1000 for NTLM) on the specified hash file."""
    cmd = ["hashcat", "-m", "1000", "-a", "0", hash_file, wordlist, "--quiet"]
    print("[*] Running Hashcat command: " + " ".join(cmd))
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("[*] Hashcat output:")
        print(result.stdout)
        if result.stderr:
            print("[!] Hashcat error output:")
            print(result.stderr)
    except Exception as e:
        print(f"[!] Failed to run Hashcat: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Parse a v0x502 keytab file correctly, extracting RC4-HMAC (NTLM) or AES keys. "
                    "If --crack is specified, automatically try to crack NTLM hashes with Hashcat.",
        epilog="Example:\n  ./fixed_keytab_extract.py child-admin.keytab --crack --wordlist rockyou.txt"
    )
    parser.add_argument("keytab", help="Path to the keytab file")
    parser.add_argument("--crack", action="store_true", help="Attempt to crack NTLM hashes using Hashcat")
    parser.add_argument("--wordlist", help="Path to the wordlist (required if --crack is used)")
    args = parser.parse_args()

    if args.crack and not args.wordlist:
        parser.error("--crack requires --wordlist to be specified.")

    # Read the keytab file into memory
    try:
        with open(args.keytab, "rb") as f:
            file_data = f.read()
    except IOError as e:
        print(f"[!] Could not open keytab file: {e}")
        sys.exit(1)

    # Parse the entire keytab
    entries = parse_keytab(file_data)
    if not entries:
        print("[!] No entries found in the keytab file.")
        sys.exit(1)

    # Collect any NTLM (RC4-HMAC) hashes for optional cracking
    ntlm_hashes = []

    for entry in entries:
        print("Principal:     ", entry["principal"])
        print("Timestamp:     ", entry["timestamp"])
        print("Key Version:   ", entry["key_vno"])

        if entry["key_type"] == 23:
            # RC4-HMAC => NTLM
            hash_val = entry["key"].hex()
            print("Key Type:       23 (RC4-HMAC / NTLM)")
            print("NTLM Hash Only: ", hash_val)
            ntlm_hashes.append(hash_val)
        elif entry["key_type"] == 17:
            # AES-128
            print("Key Type:       17 (AES-128-CTS-HMAC-SHA1)")
            print("AES-128 Key:    ", entry["key"].hex())
        elif entry["key_type"] == 18:
            # AES-256
            print("Key Type:       18 (AES-256-CTS-HMAC-SHA1)")
            print("AES-256 Key:    ", entry["key"].hex())
        else:
            # Could be DES or something else
            print(f"Key Type:       {entry['key_type']} (Unrecognized/Other)")
            print("Key (Hex):      ", entry["key"].hex())

        print("-" * 60)

    # If --crack is specified and we have NTLM hashes, run Hashcat
    if args.crack and ntlm_hashes:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            for h in ntlm_hashes:
                tmp.write(h + "\n")
            hash_file = tmp.name
        print(f"[*] NTLM hashes written to temporary file: {hash_file}")

        run_hashcat(hash_file, args.wordlist)

        # Remove the temp file
        os.remove(hash_file)
    elif args.crack:
        print("[!] No NTLM (RC4-HMAC) hashes found to crack.")

if __name__ == "__main__":
    main()