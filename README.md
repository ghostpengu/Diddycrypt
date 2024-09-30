
# Diddy Crypt

**Diddy Crypt** is a simple command-line encryption and decryption tool for securing folders. It leverages AES-128 encryption in CBC mode, salted key derivation using SHA-256, and zips/unzips folders before and after encryption. This tool can securely lock and unlock your folder using password-based encryption.

## Features

- **AES-128-CBC Encryption**: Uses AES-128 in CBC mode with PKCS7 padding for secure encryption.
- **Password-based Key Derivation**: Passwords are combined with a random salt using SHA-256 to derive the encryption key.
- **Folder Encryption**: Folders are compressed into a zip archive before encryption, allowing easy encryption of multiple files.
- **Secure Decryption**: Unlocks the encrypted folder by decrypting and extracting the contents.
- **Simple CLI**: Minimalistic command-line interface for ease of use.

## Requirements

- Rust (to build and run the project)
- Libraries: `aes`, `block-modes`, `sha2`, `rand`, `zip`

## Usage

1. **Start the encryption process**:
   ```bash
   cargo run
   ```

2. **Commands**:
   - **`start`**: Initializes a folder named `data/` for encryption.
   - **`lock`**: Zips and encrypts the `data/` folder, and stores the result in `encrypted_data.bin`. The `data/` folder is removed after encryption.
   - **`unlock`**: Prompts for the password to decrypt and restore the contents of the `encrypted_data.bin` back into the `data/` folder. The `encrypted_data.bin` file is removed after successful decryption.

3. **Encryption Example**:
   - Start by creating the `data/` folder with `start`.
   - Add the files you want to encrypt inside the `data/` folder.
   - Use `lock` to encrypt the folder.

4. **Decryption Example**:
   - Run the `unlock` command and provide the password used during encryption to restore the contents of the `data/` folder.

## Example

```bash
> cargo run
WELCOME TO DIDDY CRYPT

use 'start' to initialize diddy
use 'lock' to crypt folder
use 'unlock' to uncrypt folder
>
> start
> # Creates data folder
> lock
Encrypted data saved to 'encrypted_data.bin'
> unlock
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ghostpengu/Diddycrypt.git
   cd Diddycrypt
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

3. Run the project:
   ```bash
   cargo run
   ```
