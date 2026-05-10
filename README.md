# WHO_V3

I wrote this to move encrypted zip data through audio files for storage/transfer experiments. It’s not complicated, just layered enough to be annoying.

based on code from previous repos, 
- https://github.com/jackhession/AES_Encryption
- https://github.com/jackhession/ohWrD-Encryption (dont use this one it's stupid)
## What it does

- Takes a `.zip` file
- Encrypts it using AES-GCM
- Splits the encrypted data into chunks
- Appends those chunks to audio files in a folder
- Reassembles and decrypts the data later

## Encryption details

- AES-256-GCM
- PBKDF2 (200,000 iterations)
- 16-byte random salt per encryption
- SHA-256 used to verify each chunk

## Usage

### Encrypt

python drwho.py encrypt <audio_folder> <zip_file> <password>

- Reads the zip file
- Encrypts it
- Splits it into chunks
- Appends chunks to each audio file in the folder

### Decrypt

python drwho.py decrypt <audio_folder> <password>

- Scans audio files for embedded chunks
- Extracts and verifies them
- Rebuilds the encrypted payload
- Decrypts into output.zip

## Data marker

WHO_V3::

## Failure cases

- Wrong password → decryption fails and .safe.py is executed
- Corrupted chunks → skipped during extraction
- Broken zip → triggers integrity check and .safe.py

## Output

output.zip

## Notes

- Audio files are modified directly
- No backup is created
- Assumes correct usage and valid inputs
