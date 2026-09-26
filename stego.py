import os
import sys
import time
import struct
import argparse
from PIL import Image
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"STG1"
HEADER_LEN = 36  # [4B magic] [12B nonce] [16B tag] [4B ct_len]
SALT = b"stego_fixed_salt_v1"  # TODO: store random per-image salt in header if migrating to multi-tenant

def derive_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
    )
    return kdf.derive(passphrase.encode("utf-8"))

def get_capacity(img: Image.Image) -> int:
    # 3 bits per pixel (R, G, B). Alpha is left untouched to prevent transparency speckles.
    total_bits = img.width * img.height * 3
    total_bytes = total_bits // 8
    return max(0, total_bytes - HEADER_LEN)

def embed_bytes(img: Image.Image, data: bytes, key: bytes) -> Image.Image:
    # TODO: support palette P-mode images directly without converting
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")

    nonce = os.urandom(12)
    cipher = AESGCM(key)
    raw = cipher.encrypt(nonce, data, MAGIC)
    ct, tag = raw[:-16], raw[-16:]

    hdr = struct.pack(">4s12s16sI", MAGIC, nonce, tag, len(ct))
    packet = hdr + ct

    total_bits = len(packet) * 8
    max_bits = img.width * img.height * 3
    if total_bits > max_bits:
        raise ValueError(f"Payload too large ({len(packet)}B). Carrier max is {max_bits // 8}B")

    bits = [(b >> s) & 1 for b in packet for s in (7, 6, 5, 4, 3, 2, 1, 0)]
    pixels = bytearray(img.tobytes())

    if img.mode == "RGBA":
        bit_idx = 0
        for i in range(0, len(pixels), 4):
            for c in range(3):
                if bit_idx < len(bits):
                    pixels[i + c] = (pixels[i + c] & ~1) | bits[bit_idx]
                    bit_idx += 1
                else:
                    break
            if bit_idx >= len(bits):
                break
    else:
        for i in range(len(bits)):
            pixels[i] = (pixels[i] & ~1) | bits[i]

    return Image.frombytes(img.mode, img.size, bytes(pixels))

def extract_bytes(img: Image.Image, key: bytes) -> bytes:
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")

    pixels = img.tobytes()
    mode = img.mode

    def channels():
        if mode == "RGBA":
            for i in range(0, len(pixels), 4):
                yield pixels[i]
                yield pixels[i + 1]
                yield pixels[i + 2]
        else:
            for b in pixels:
                yield b

    def read_n(gen, n):
        out = bytearray()
        for _ in range(n):
            val = 0
            for shift in (7, 6, 5, 4, 3, 2, 1, 0):
                try:
                    ch = next(gen)
                except StopIteration:
                    return None
                val |= (ch & 1) << shift
            out.append(val)
        return bytes(out)

    gen = channels()
    hdr = read_n(gen, HEADER_LEN)
    if not hdr:
        return None

    magic, nonce, tag, ct_len = struct.unpack(">4s12s16sI", hdr)
    if magic != MAGIC:
        return None

    cap = get_capacity(img)
    if ct_len > cap:
        return None

    ct = read_n(gen, ct_len)
    if not ct or len(ct) != ct_len:
        return None

    cipher = AESGCM(key)
    try:
        return cipher.decrypt(nonce, ct + tag, MAGIC)
    except InvalidTag:
        return None

def run_tests():
    print("running tests...")

    img = Image.new("RGB", (200, 200), color=(70, 130, 180))
    key = os.urandom(32)
    secret = b"Classified operative coordinates: 37.7749N, 122.4194W"

    stego_img = embed_bytes(img, secret, key)
    extracted = extract_bytes(stego_img, key)
    assert extracted == secret
    print("[stego] embed+extract: PASS")

    tampered_bytes = bytearray(stego_img.tobytes())
    tampered_bytes[100] ^= 0x01
    tampered_img = Image.frombytes(stego_img.mode, stego_img.size, bytes(tampered_bytes))
    assert extract_bytes(tampered_img, key) is None
    print("[stego] tampered pixel: PASS")

    bad_key = os.urandom(32)
    assert extract_bytes(stego_img, bad_key) is None
    print("[stego] wrong key: PASS")

    clean_img = Image.new("RGB", (100, 100), color=(255, 0, 0))
    assert extract_bytes(clean_img, key) is None
    print("[stego] clean carrier: PASS")

    tiny_img = Image.new("RGB", (10, 10))
    try:
        embed_bytes(tiny_img, b"X" * 1000, key)
        assert False
    except ValueError:
        print("[stego] overflow guard: PASS\n")

def run_benchmark():
    img = Image.new("RGB", (500, 500), color=(30, 30, 30))
    key = os.urandom(32)
    cap = get_capacity(img)
    print(f"Carrier: 500x500 RGB | Usable payload capacity: {cap:,} bytes (~{cap // 1024} KB)")

    test_payload = os.urandom(16 * 1024)
    rounds = 30

    t0 = time.time()
    for _ in range(rounds):
        stego_img = embed_bytes(img, test_payload, key)
    embed_time = time.time() - t0

    t1 = time.time()
    for _ in range(rounds):
        res = extract_bytes(stego_img, key)
    extract_time = time.time() - t1

    total_mb = (len(test_payload) * rounds) / (1024 * 1024)
    print(f"Payload: 16 KB across {rounds} runs")
    print(f"Embed speed:   {total_mb / embed_time:.2f} MB/s ({embed_time / rounds * 1000:.2f} ms/embed)")
    print(f"Extract speed: {total_mb / extract_time:.2f} MB/s ({extract_time / rounds * 1000:.2f} ms/extract)\n")

def main():
    parser = argparse.ArgumentParser(description="Encrypted image steganography utility")
    subparsers = parser.add_subparsers(dest="command")

    p_embed = subparsers.add_parser("embed", help="Embed secret data into an image")
    p_embed.add_argument("--image", required=True, help="Input carrier image (PNG, BMP)")
    p_embed.add_argument("--out", required=True, help="Output stego image path (.png)")
    p_embed.add_argument("--text", type=str, help="Secret text message to embed")
    p_embed.add_argument("--file", type=str, help="Secret file to embed")
    p_embed.add_argument("--password", type=str, help="Password for AES-GCM encryption")
    p_embed.add_argument("--key", type=str, help="32-byte hex key")

    p_extract = subparsers.add_parser("extract", help="Extract secret data from an image")
    p_extract.add_argument("--image", required=True, help="Input stego image path")
    p_extract.add_argument("--out", type=str, help="Save extracted data to file (optional)")
    p_extract.add_argument("--password", type=str, help="Password used during embedding")
    p_extract.add_argument("--key", type=str, help="32-byte hex key")

    p_cap = subparsers.add_parser("capacity", help="Check maximum payload size for an image")
    p_cap.add_argument("--image", required=True, help="Carrier image path")

    subparsers.add_parser("test", help="Run automated test suite")
    subparsers.add_parser("benchmark", help="Run throughput benchmark")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        run_tests()
        run_benchmark()
        return

    if args.command == "test":
        run_tests()
        return

    if args.command == "benchmark":
        run_benchmark()
        return

    if args.command == "capacity":
        img = Image.open(args.image)
        cap = get_capacity(img)
        print(f"Image: {args.image} ({img.width}x{img.height} {img.mode})")
        print(f"Max payload capacity: {cap:,} bytes (~{cap // 1024} KB)")
        return

    key = bytes.fromhex(args.key) if args.key else (derive_key(args.password) if args.password else os.urandom(32))

    if args.command == "embed":
        if args.out.lower().endswith(".jpg") or args.out.lower().endswith(".jpeg"):
            print("Error: JPEG uses lossy compression which destroys LSB bits. Use PNG or BMP.")
            sys.exit(1)

        if args.text:
            data = args.text.encode("utf-8")
        elif args.file:
            with open(args.file, "rb") as f:
                data = f.read()
        else:
            print("Error: Provide either --text or --file to embed.")
            sys.exit(1)

        img = Image.open(args.image)
        stego_img = embed_bytes(img, data, key)
        stego_img.save(args.out, format="PNG")
        print(f"Successfully embedded {len(data)} bytes into {args.out}")

    elif args.command == "extract":
        img = Image.open(args.image)
        recovered = extract_bytes(img, key)
        if recovered is None:
            print("Failed: No valid secret found (corrupted image or wrong key/password).")
            sys.exit(1)

        if args.out:
            with open(args.out, "wb") as f:
                f.write(recovered)
            print(f"Saved extracted secret to {args.out} ({len(recovered)} bytes)")
        else:
            try:
                print(f"Extracted secret: {recovered.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f"Extracted binary payload: {len(recovered)} bytes (use --out <file> to save)")

if __name__ == "__main__":
    main()
