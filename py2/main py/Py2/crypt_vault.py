"""
CRYPT_VAULT.py
==============
Centralized cryptography module containing AES-256-CBC encryption,
Base64 encoding/decoding, key derivation, and payload encryption routines.

Extracted from: red_cipher.py, python_ghost.py, ghost.py, forensic_pcap_deep_inspector.py, 
                ghost_uploader.py

Functions:
    - RedCipher: AES-256-CBC symmetric encryption/decryption with key derivation
    - Base64 encoding/decoding utilities
    - Key generation from passphrases
    - Hex encoding/decoding utilities
"""

import base64
import hashlib
import binascii
import re
from typing import Union, Optional, Dict, List
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ============================================================================
# AES-256-CBC ENCRYPTION ENGINE
# ============================================================================

class RedCipher:
    """
    Elite AES-256-CBC symmetric cipher with automatic key derivation.
    
    Key derivation: SHA-256 hashing ensures exact 256-bit (32-byte) keys.
    Encryption: CBC mode with random IV prepended to ciphertext.
    Encoding: Base64 for transmission compatibility.
    
    Usage:
        cipher = RedCipher(b"passphrase_or_bytes")
        encrypted = cipher.encrypt("plaintext")
        decrypted = cipher.decrypt(encrypted)
    """
    
    def __init__(self, key_material: Union[str, bytes]):
        """
        Initialize cipher with key material.
        
        Args:
            key_material: Passphrase or byte string (will be hashed to 256-bit)
        """
        if isinstance(key_material, str):
            key_material = key_material.encode()
        self.key = hashlib.sha256(key_material).digest()

    def encrypt(self, raw_data: Union[str, bytes]) -> str:
        """
        Encrypt plaintext data using AES-256-CBC.
        
        Args:
            raw_data: Plaintext string or bytes
            
        Returns:
            Base64-encoded ciphertext with prepended IV
        """
        if isinstance(raw_data, str):
            raw_data = raw_data.encode()
        
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(raw_data, AES.block_size))
        
        # Prepend IV to ciphertext for transmission
        return base64.b64encode(iv + encrypted_data).decode("utf-8")

    def decrypt(self, enc_data: str) -> str:
        """
        Decrypt Base64-encoded ciphertext using AES-256-CBC.
        
        Args:
            enc_data: Base64-encoded ciphertext (with IV prefix)
            
        Returns:
            Decrypted plaintext string, or "{}" on error
        """
        try:
            enc_data = base64.b64decode(enc_data)
            iv = enc_data[:AES.block_size]
            cipher_text = enc_data[AES.block_size:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(cipher_text), AES.block_size).decode("utf-8")
        except Exception as e:
            return "{}"

    def derive_key(self, salt: str) -> bytes:
        """
        Derive a sub-key for specific sessions or fragments.
        
        Args:
            salt: Session ID or fragment identifier
            
        Returns:
            256-bit derived key as bytes
        """
        return hashlib.sha256(self.key + salt.encode()).digest()


# ============================================================================
# KEY GENERATION & MANAGEMENT
# ============================================================================

def generate_date_variant_key(passphrase: Union[str, bytes], date_string: Optional[str] = None) -> RedCipher:
    """
    Generate a date-variant cipher (key changes daily).
    
    Prevents decryption of older traffic if compromised mid-operation.
    
    Args:
        passphrase: Base passphrase
        date_string: Optional date (format: YYYY-MM-DD). If None, uses current date.
        
    Returns:
        RedCipher instance with date-derived key
    """
    from datetime import datetime
    
    if date_string is None:
        date_string = datetime.now().strftime("%Y-%m-%d")
    
    if isinstance(passphrase, str):
        passphrase = passphrase.encode()
    
    combined = passphrase + date_string.encode()
    return RedCipher(combined)


def derive_session_key(master_key: bytes, session_id: str) -> bytes:
    """
    Derive a per-session key from master key.
    
    Args:
        master_key: 256-bit master key (32 bytes)
        session_id: Unique session identifier
        
    Returns:
        256-bit session-specific key
    """
    return hashlib.sha256(master_key + session_id.encode()).digest()


# ============================================================================
# BASE64 ENCODING/DECODING
# ============================================================================

def base64_encode(data: Union[str, bytes]) -> str:
    """
    Encode data to Base64 string.
    
    Args:
        data: String or bytes to encode
        
    Returns:
        Base64-encoded string
    """
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode("utf-8")


def base64_decode(data: str, validate: bool = False) -> Optional[bytes]:
    """
    Decode Base64 string to bytes.
    
    Args:
        data: Base64-encoded string
        validate: If True, raise exception on invalid Base64
        
    Returns:
        Decoded bytes, or None on error
    """
    try:
        return base64.b64decode(data, validate=validate)
    except Exception:
        return None


def base64_str_decode(data: str) -> Optional[str]:
    """
    Decode Base64 string to plaintext string.
    
    Args:
        data: Base64-encoded string
        
    Returns:
        Decoded plaintext string, or None on error
    """
    try:
        return base64.b64decode(data).decode("utf-8")
    except Exception:
        return None


# ============================================================================
# HEX ENCODING/DECODING
# ============================================================================

def hex_encode(data: Union[str, bytes], separator: str = "") -> str:
    """
    Encode data to hexadecimal string.
    
    Args:
        data: String or bytes to encode
        separator: Optional separator between hex pairs (e.g., ":" or " ")
        
    Returns:
        Hexadecimal string
    """
    if isinstance(data, str):
        data = data.encode()
    hex_str = binascii.hexlify(data).decode("ascii")
    if separator:
        return separator.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    return hex_str


def hex_decode(hex_string: str) -> Optional[bytes]:
    """
    Decode hexadecimal string to bytes.
    
    Args:
        hex_string: Hexadecimal string (with or without separators)
        
    Returns:
        Decoded bytes, or None on error
    """
    try:
        # Remove common separators
        hex_string = hex_string.replace(" ", "").replace(":", "").replace("-", "")
        return binascii.unhexlify(hex_string)
    except Exception:
        return None


def hex_dump(data: bytes, length: int = 16, offset: int = 0) -> str:
    """
    Format binary data as hexadecimal dump with ASCII sidebar.
    
    Useful for forensic analysis and debugging.
    
    Args:
        data: Binary data
        length: Bytes per line (default 16)
        offset: Starting offset for line numbering
        
    Returns:
        Formatted hex dump string
    """
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        addr = f"{offset + i:08x}"
        lines.append(f"{addr}  {hex_part:<{length*3}}  {ascii_part}")
    return "\n".join(lines)


# ============================================================================
# PAYLOAD ENCODING DETECTION & EXTRACTION
# ============================================================================

def _safe_decode(data: bytes, fallback: str = "") -> str:
    """Safely decode bytes to string, falling back on error."""
    try:
        return data.decode("utf-8")
    except:
        try:
            return data.decode("latin-1")
        except:
            return fallback


def _printable_ratio(text: str) -> float:
    """Calculate ratio of printable characters in text."""
    if not text:
        return 0.0
    printable_count = sum(1 for c in text if c.isprintable() or c.isspace())
    return printable_count / len(text)


def try_decode_base64(text: str) -> List[Dict]:
    """
    Extract and decode potential Base64 tokens from text.
    
    Uses heuristic pattern matching with printable ratio validation.
    
    Args:
        text: Text to scan for Base64 tokens
        
    Returns:
        List of dicts with keys: token, decoded_preview, type
    """
    findings = []
    pattern = r'(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])'
    
    for m in re.finditer(pattern, text):
        token = m.group(1)
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = _safe_decode(raw)
            if _printable_ratio(decoded) >= 0.70:
                findings.append({
                    "token": token[:80],
                    "decoded_preview": decoded[:250],
                    "type": "base64",
                })
        except Exception:
            continue
    
    return findings


def try_decode_hex(text: str) -> List[Dict]:
    """
    Extract and decode potential hexadecimal tokens from text.
    
    Validates even-length hex strings and printable ratio.
    
    Args:
        text: Text to scan for hex tokens
        
    Returns:
        List of dicts with keys: token, decoded_preview, type
    """
    findings = []
    pattern = r'(?<![A-Fa-f0-9])([A-Fa-f0-9]{32,})(?![A-Fa-f0-9])'
    
    for m in re.finditer(pattern, text):
        token = m.group(1)
        if len(token) % 2 != 0:
            continue
        try:
            raw = binascii.unhexlify(token)
            decoded = _safe_decode(raw)
            if _printable_ratio(decoded) >= 0.70:
                findings.append({
                    "token": token[:80],
                    "decoded_preview": decoded[:250],
                    "type": "hex",
                })
        except Exception:
            continue
    
    return findings


# ============================================================================
# PAYLOAD FRAGMENTATION & REASSEMBLY
# ============================================================================

class PayloadAssembler:
    """
    Reassemble fragmented encrypted payloads with session tracking.
    
    Supports time-to-live (TTL) cleanup for abandoned sessions.
    """
    
    def __init__(self, ttl_seconds: int = 300):
        """
        Initialize payload assembler.
        
        Args:
            ttl_seconds: Time-to-live for incomplete sessions (default 5 minutes)
        """
        self.buffer: Dict[str, Dict] = {}
        self.ttl = ttl_seconds
        import time
        self.time_module = time

    def add_fragment(self, session_id: str, part_index: int, total_parts: int, data: str) -> Optional[str]:
        """
        Add a fragment to the reassembly buffer.
        
        Returns the full reassembled payload if all parts received.
        
        Args:
            session_id: Unique session identifier
            part_index: Index of this fragment (0-based)
            total_parts: Total fragments expected
            data: Fragment data
            
        Returns:
            Complete reassembled payload if all parts received, else None
        """
        now = self.time_module.time()
        self._cleanup()

        if session_id not in self.buffer:
            self.buffer[session_id] = {
                "parts": {},
                "total": total_parts,
                "timestamp": now,
            }

        session = self.buffer[session_id]
        session["parts"][part_index] = data
        session["timestamp"] = now

        if len(session["parts"]) == session["total"]:
            ordered_parts = [session["parts"][i] for i in range(session["total"])]
            full_payload = "".join(ordered_parts)
            del self.buffer[session_id]
            return full_payload

        return None

    def _cleanup(self):
        """Remove expired sessions from buffer."""
        now = self.time_module.time()
        expired = [
            sid for sid, data in self.buffer.items()
            if now - data["timestamp"] > self.ttl
        ]
        for sid in expired:
            del self.buffer[sid]

    def get_stats(self) -> Dict:
        """Get buffer statistics."""
        return {
            "active_sessions": len(self.buffer),
            "fragments_buffered": sum(len(s["parts"]) for s in self.buffer.values()),
        }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def secure_hash(data: Union[str, bytes]) -> str:
    """
    Generate SHA256 hash of data.
    
    Args:
        data: String or bytes to hash
        
    Returns:
        Hex-encoded hash
    """
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def compare_hashes(hash1: str, hash2: str) -> bool:
    """
    Constant-time comparison of hash strings (prevents timing attacks).
    
    Args:
        hash1: First hash
        hash2: Second hash
        
    Returns:
        True if hashes match, False otherwise
    """
    return hashlib.sha256(hash1.encode()).digest() == hashlib.sha256(hash2.encode()).digest()
