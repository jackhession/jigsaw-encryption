import os
import zipfile
import subprocess
import hashlib

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

TRACK_DIR = "audio_tracks"
MAGIC = b"WHO_DATA_V2::"


# ---------------- KEY DERIVATION ----------------

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=200000)


# ---------------- ENCRYPT / DECRYPT ----------------

def encrypt(data, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return salt + cipher.nonce + tag + ciphertext


def decrypt(data, password):
    salt = data[:16]
    nonce = data[16:32]
    tag = data[32:48]
    ciphertext = data[48:]

    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ---------------- CHUNKING ----------------

def split_data(data, parts, redundancy=1):
    chunk_size = len(data) // parts

    chunks = [
        data[i * chunk_size:(i + 1) * chunk_size]
        for i in range(parts - 1)
    ]
    chunks.append(data[(parts - 1) * chunk_size:])

    # redundancy (optional duplication)
    expanded = []
    for c in chunks:
        for _ in range(redundancy):
            expanded.append(c)

    return expanded


# ---------------- CHUNK PACKING ----------------

def make_chunk(data, index):
    sha = hashlib.sha256(data).digest()

    header = (
        MAGIC +
        index.to_bytes(2, "big") +
        len(data).to_bytes(4, "big") +
        sha
    )

    return header + data


# ---------------- EMBED INTO AUDIO FILES ----------------

def embed_chunks(chunks, tracks):
    for i, track in enumerate(tracks):
        chunk = chunks[i] if i < len(chunks) else b""
        payload = make_chunk(chunk, i)

        with open(track, "ab") as f:
            f.write(payload)


# ---------------- EXTRACT FROM AUDIO FILES ----------------

def extract_chunks(tracks):
    chunks = {}

    for track in tracks:
        with open(track, "rb") as f:
            data = f.read()

        idx = data.rfind(MAGIC)
        if idx == -1:
            continue

        start = idx + len(MAGIC)

        index = int.from_bytes(data[start:start+2], "big")
        size = int.from_bytes(data[start+2:start+6], "big")
        expected_hash = data[start+6:start+38]
        chunk = data[start+38:start+38+size]

        actual_hash = hashlib.sha256(chunk).digest()

        if actual_hash != expected_hash:
            print(f"[!] Corrupted chunk {index} detected, skipping.")
            continue

        chunks[index] = chunk

    return [chunks[i] for i in sorted(chunks)]


# ---------------- ENCRYPT FLOW ----------------

def drwho_encrypt(filename, password):
    print(f"[+] Encrypting {filename}...")

    with open(filename, "rb") as f:
        data = f.read()

    encrypted = encrypt(data, password)

    if not os.path.exists(TRACK_DIR):
        print("audio_tracks folder missing!")
        return

    tracks = sorted([
        os.path.join(TRACK_DIR, f)
        for f in os.listdir(TRACK_DIR)
        if os.path.isfile(os.path.join(TRACK_DIR, f))
    ])

    chunks = split_data(encrypted, len(tracks), redundancy=1)

    embed_chunks(chunks, tracks)

    print("[+] Data embedded into audio tracks.")


# ---------------- DECRYPT FLOW ----------------

def drwho_decrypt(password):
    print("[+] Reconstructing data...")

    if not os.path.exists(TRACK_DIR):
        print("audio_tracks folder missing!")
        return

    tracks = sorted([
        os.path.join(TRACK_DIR, f)
        for f in os.listdir(TRACK_DIR)
        if os.path.isfile(os.path.join(TRACK_DIR, f))
    ])

    chunks = extract_chunks(tracks)

    if not chunks:
        print("No valid data found!")
        return

    encrypted = b"".join(chunks)

    try:
        decrypted = decrypt(encrypted, password)
    except Exception:
        print("Wrong password or corrupted archive!")
        subprocess.run(["python3", ".safe.py"])
        return

    with open("output.zip", "wb") as f:
        f.write(decrypted)

    print("[+] output.zip recovered successfully.")


# ---------------- MAIN ----------------

key1 = input("Key: ")
key2 = input("Verify key: ")

if key1 != key2:
    print("Keys do not match.")
    exit()

zip_found = False
ohwrd_found = False

for file in os.listdir():
    if file.endswith(".zip"):
        zip_found = True
    elif file.endswith(".ohwrd2"):
        ohwrd_found = True

if zip_found:
    print("[*] Encrypting + embedding into audio tracks...")
    for file in os.listdir():
        if file.endswith(".zip"):
            drwho_encrypt(file, key1)

elif ohwrd_found:
    print("[*] Extracting + decrypting...")
    drwho_decrypt(key1)

else:
    print("No .zip or .ohwrd2 files found.")


# ---------------- ZIP VALIDATION ----------------

try:
    if os.path.exists("output.zip"):
        with zipfile.ZipFile("output.zip", "r") as z:
            z.testzip()
except zipfile.BadZipFile:
    print("ZIP corrupted after recovery!")
    subprocess.run(["python3", ".safe.py"])