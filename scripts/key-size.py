#!/usr/bin/env -S uv run --script

# Calculate armored PGP key sizes based on base64 encoding

import math


# Base64 encoding formula: ceil(n/3) * 4 for padded output
def calculate_base64_length(binary_bytes):
    """Calculate base64 encoded length from binary bytes"""
    return math.ceil(binary_bytes / 3) * 4


# RSA key sizes and typical private key binary sizes
# A typical RSA private key contains: modulus, public exponent, private exponent,
# primes p and q, and additional values for CRT optimization

rsa_key_data = {
    "RSA 1024-bit": {
        "key_bits": 1024,
        "modulus_bytes": 128,
        "approx_private_key_der": 608,  # approximate DER encoded size
    },
    "RSA 2048-bit": {
        "key_bits": 2048,
        "modulus_bytes": 256,
        "approx_private_key_der": 1192,  # approximate DER encoded size
    },
    "RSA 3072-bit": {
        "key_bits": 3072,
        "modulus_bytes": 384,
        "approx_private_key_der": 1768,  # approximate DER encoded size
    },
    "RSA 4096-bit": {
        "key_bits": 4096,
        "modulus_bytes": 512,
        "approx_private_key_der": 2344,  # approximate DER encoded size
    },
}

# EdDSA key sizes (fixed)
eddsa_key_data = {
    "Ed25519": {"private_key_bytes": 32, "public_key_bytes": 32, "signature_bytes": 64},
    "Ed448": {"private_key_bytes": 57, "public_key_bytes": 57, "signature_bytes": 114},
}

print("=" * 80)
print("PGP ARMORED KEY SIZE ESTIMATES")
print("=" * 80)

print("\n### RSA PRIVATE KEYS ###\n")

for key_type, data in rsa_key_data.items():
    # PGP private key includes additional metadata, subkeys, etc.
    # Rough estimate: DER size + 20-40% for PGP packet overhead
    estimated_pgp_binary = data["approx_private_key_der"] * 1.3

    base64_chars = calculate_base64_length(estimated_pgp_binary)

    # Armored format typically has 64 characters per line
    lines = math.ceil(base64_chars / 64)

    # Add lines for header, version, comment, blank line, checksum (~5-10 lines overhead)
    total_lines = lines + 8

    # Total characters including newlines and armor headers
    armor_header = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
    armor_footer = "-----END PGP PRIVATE KEY BLOCK-----\n"
    total_chars = (
        len(armor_header) + base64_chars + lines + len(armor_footer) + 200
    )  # +200 for Version/Comment headers

    print(f"{key_type}:")
    print(f"  Binary size (approx): {int(estimated_pgp_binary)} bytes")
    print(f"  Base64 encoded: {int(base64_chars)} characters")
    print(f"  Armored lines (64 chars/line): ~{lines} lines of base64")
    print(f"  Total armored lines: ~{total_lines} lines (including headers)")
    print(f"  Total armored size: ~{int(total_chars)} characters\n")

print("\n### EdDSA KEYS (PGP format) ###\n")

for key_type, data in eddsa_key_data.items():
    # PGP EdDSA keys are much smaller
    # Rough estimate for PGP packet including metadata
    estimated_pgp_binary = (
        data["private_key_bytes"] * 2.5
    )  # very rough estimate with PGP overhead

    base64_chars = calculate_base64_length(estimated_pgp_binary)
    lines = math.ceil(base64_chars / 64)
    total_lines = lines + 8

    armor_header = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
    armor_footer = "-----END PGP PRIVATE KEY BLOCK-----\n"
    total_chars = len(armor_header) + base64_chars + lines + len(armor_footer) + 200

    print(f"{key_type}:")
    print(f"  Private key (raw): {data['private_key_bytes']} bytes")
    print(f"  Binary size (approx with PGP): {int(estimated_pgp_binary)} bytes")
    print(f"  Base64 encoded: {int(base64_chars)} characters")
    print(f"  Armored lines: ~{lines} lines of base64")
    print(f"  Total armored lines: ~{total_lines} lines")
    print(f"  Total armored size: ~{int(total_chars)} characters\n")

print("\n" + "=" * 80)
print("TYPICAL LINE COUNT RANGES FOR ARMORED PRIVATE KEYS")
print("=" * 80)
print("\nRSA 2048-bit: 26-30 lines")
print("RSA 4096-bit: 48-55 lines")
print("Ed25519: 8-12 lines")
print("\n(Note: Actual sizes vary based on subkeys, metadata, and implementation)")
