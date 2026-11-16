import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
from PIL.PngImagePlugin import PngInfo

MODES = ("ECB", "CBC", "CTR", "OFB")   # ECB/CBC/CTR are required, OFB is a bonus


class WrongKeyError(Exception):
    pass


class NotEncryptedError(Exception):
    pass


def generate_key(size=32):
    """size = 16 / 24 / 32 bytes (AES-128 / 192 / 256)"""
    return get_random_bytes(size)


def key_id(key):
    """Short fingerprint of the key (used to detect a wrong key and to name key files)."""
    return hashlib.sha256(key).hexdigest()[:8]


def save_key(key, path):
    with open(path, "w") as f:
        f.write(key.hex())


def load_key(path):
    with open(path) as f:
        return bytes.fromhex(f.read().strip())


def read_info(path):
    """Return the metadata dict if the image was produced by this app, else None."""
    try:
        img = Image.open(path)
        info = dict(getattr(img, "text", {}) or {})
    except Exception:
        return None
    return info if "mode" in info and "tail" in info else None


def encrypt_image(in_path, out_path, key, mode):
    img = Image.open(in_path).convert("RGB")
    w, h = img.size
    raw = img.tobytes()                       # raw RGB pixel bytes
    meta = PngInfo()
    meta.add_text("mode", mode)
    meta.add_text("kid", key_id(key))

    if mode == "ECB":
        ct = AES.new(key, AES.MODE_ECB).encrypt(pad(raw, AES.block_size))
    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC)   # random IV
        ct = cipher.encrypt(pad(raw, AES.block_size))
        meta.add_text("iv", cipher.iv.hex())
    elif mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR)   # random nonce
        ct = cipher.encrypt(raw)
        meta.add_text("nonce", cipher.nonce.hex())
    elif mode == "OFB":
        cipher = AES.new(key, AES.MODE_OFB)   # random IV, stream mode (no padding)
        ct = cipher.encrypt(raw)
        meta.add_text("iv", cipher.iv.hex())
    else:
        raise ValueError("Unknown mode")

    n = w * h * 3
    meta.add_text("tail", ct[n:].hex())       # padding bytes that don't fit in the image
    Image.frombytes("RGB", (w, h), ct[:n]).save(out_path, pnginfo=meta)


def decrypt_to_image(in_path, key):
    """Decrypt and return (PIL image, mode). Raises NotEncryptedError / WrongKeyError."""
    info = read_info(in_path)
    if info is None:
        raise NotEncryptedError("This file was not encrypted by this application.")
    if info.get("kid") and info["kid"] != key_id(key):
        raise WrongKeyError("Wrong key: this image was encrypted with a different key.")

    mode = info["mode"]
    img = Image.open(in_path)
    w, h = img.size
    ct = img.convert("RGB").tobytes() + bytes.fromhex(info["tail"])

    try:
        if mode == "ECB":
            pt = unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), AES.block_size)
        elif mode == "CBC":
            iv = bytes.fromhex(info["iv"])
            pt = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), AES.block_size)
        elif mode == "CTR":
            nonce = bytes.fromhex(info["nonce"])
            pt = AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ct)
        elif mode == "OFB":
            iv = bytes.fromhex(info["iv"])
            pt = AES.new(key, AES.MODE_OFB, iv=iv).decrypt(ct)
        else:
            raise ValueError("Unknown mode")
    except ValueError as e:
        raise WrongKeyError("Wrong key or corrupted image.") from e

    return Image.frombytes("RGB", (w, h), pt), mode


def decrypt_image(in_path, out_path, key):
    img, mode = decrypt_to_image(in_path, key)
    img.save(out_path)
    return mode


def verify(original_path, encrypted_path, key):
    """True if decrypting encrypted_path gives back exactly the original pixels."""
    img, _ = decrypt_to_image(encrypted_path, key)
    return img.tobytes() == Image.open(original_path).convert("RGB").tobytes()