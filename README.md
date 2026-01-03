# WhisperTLS
A secure, truly peer-to-peer chat system with end-to-end encryption, running over Tor onion services
No central servers, no IP exposure, no metadata leakage to third parties.

##  Disclaimer
WhisperTLS is a **proof-of-concept secure messaging system** designed for privacy enthusiasts and researchers.  
Use at your own risk. The authors provide no warranties regarding security, reliability, or suitability for any purpose.

##  Key Features
- **True P2P** – Direct onion-to-onion connections, no relays or central servers.
- **Dual hidden service channels** – Both peers connect to each other’s onion services for bidirectional authentication.
- **Mutual TLS** – Both sides authenticate with preshared certificates.
- **Double Ratchet encryption** – Application-layer forward secrecy and post-compromise security.
- **Traffic analysis resistance** – Constant-rate traffic with urandom padding, fixed MTU.
- **Trust-on-First-Use (TOFU)** – Initial exchange verifies all long-term material through an ephemeral secure channel.
- **No persistent identifiers** – Identities are unique per contact (No graph correlation), Onion addresses and certificates can be rotated regularly at user request.

##  How It Works

### 1. Initial Contact (Out-of-Band Exchange)
To start a conversation:
- Alice generates an **ephemeral onion service** and shares its address with Bob via QR code, NFC, or manual entry.
- Bob connects to Alice’s ephemeral service to exchange:
  - Their **permanent onion addresses**
  - **TLS certificates** (for mutual authentication)
  - **Ephemeral X25519 public keys** (for initial Double Ratchet setup)
- This exchange happens over the ephemeral Tor service, secured with TLS, this service is mean to live only 30 seconds configurable to 1 or 2 minutes, depeding of user OpSec

### 2. Connection Setup
Once initial data is exchanged:
- Alice and Bob each host their own permanent onion services.
- They establish **two parallel TLS connections** (Alice→Bob, Bob→Alice).
- Data only flows in one way
- Mutual TLS authentication ensures each party holds the expected certificate.

### 3. Key Derivation
The initial shared secret for the Double Ratchet is derived via HKDF using:
- Random entropy from both peers
- Network identifiers (onion addresses)
- Identity public keys for signatures
- TLS ECDH shared secret
- Ephemeral X25519 shared secret

This multi-source derivation ensures that compromising one component does not break overall security.

### 4. Ongoing Communication
- All application data is encrypted with the **Double Ratchet protocol**.
- Packets are padded to a **fixed MTU** with random data before encryption, then sent at a constant rate.
- If there are no real messages, the channel sends random data to maintain traffic uniformity.

## Current Development & Roadmap
The current proof-of-concept is a terminal-based chat system that supports UTF-8 text (any language, emojis etc).

We are actively working on:

#### 1. **Web Interface**

-   A modern web UI similar to WhatsApp/Telegram
-   Accessible via Tor Browser on desktop or Android
-   Can be hosted on a VPS as a transparent bridge
-   Frontend communicates with the WhisperTLS backend via WebSocket/HTTP API

#### 2. **Secure File Transfer**

- Support for regular files, images, videos, voice notes, and stickers    
- **Method**: Ephemeral Tor Hidden Services for direct P2P file sharing    
- **Process**:
  1.  Sender creates a temporary onion service with TLS using a preshared certificate        
  2.  Receiver downloads the file over this secure channel        
  3.  Ephemeral service is automatically destroyed after transfer completion        
- No intermediate storage, no cloud servers
- **Security**: Each file transfer uses a new onion service and certificate. No reuse, no persistence.    

#### 2. **Multi-Platform Support**

- Terminal UI (current PoC)
- Web Interface (in progress)  
- Android application (planned)

## Installation & Usage

### Prerequisites

This software requires Python 3.10.XX Using pyenv ensures the correct version.
Tor running with control port enabled
 

### Steps
1. Install pyenv

```
# Update package list
sudo apt update

# Install build dependencies
sudo apt install -y make build-essential libssl-dev zlib1g-dev \
libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm \
libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

# Install pyenv
curl https://pyenv.run | bash

# IMPORTANT: Restart your shell or run these commands:
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init - bash)"

# Add pyenv to your shell permanently

echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init - bash)"' >> ~/.bashrc

# Then reload your shell configuration
source ~/.bashrc

pyenv --version
# Should show: pyenv X.X.X

pyenv install 3.10.0
```

2. Clone the repository

```
git clone https://github.com/whispertls/whispertls.git
cd whispertls
 ```
 
3. Setup and Enviroment for custom python version

```
# Set Python 3.10 for this project
pyenv local 3.10.0


# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate
```

4. Install requirements and Run

```
pip install -r requirements.txt
python main.py
```

5. Usage

If everything goes well at this point you will see some message like this:

`NcursesUI: password is not set plesae do /setpassword`

and some input text prompt: `>`

You need to set a password with `/setpassword` remember that security start on your side.
Local Application database is Encrypted with a master key of 32 bytes (256 bits) but that key is only protected with your password
Choose a good password you need to input it each time that start this application with `/login`

To check all available commands on Ncurses UI write `/help`

6. Adding a new contact

Since this is one of the critical parts of the process we will explain it in detail.

Alice start the Out of Band Exchange (OOB) with command `/oob`

This will generate code which is a ephemeral TOR hidden service domain you need to give to the person who you want to add.

Bob recive that code (hidden service domain) from an external channel and add it `/add <code>` this process connect bob as client to Alice server they exchange  their permanent tor hs domain, certificates and another important data, both applications here made internal validations.

if nothing goes wrong here Bob will get a hexadecimal verification Code that need send to Alice

Alice need to verify such code with `/verify <hex code>`

This verification process is MANDATORY because is the most IMPORTANT step on this chain of TRUST.

7. Sending messages to a contact.

Once that you already add one or more contacts, you can see then with  `/list`

Contact id is a 64 bit number in hexadecimal you can set them a nickname wiht `/nick <contact_id> <nickname>`

Select a contact to see previous messages with `/select <contact id or nick name>`

Once that a contact is selected anything you write without `/` will be considered as message and will be send on ENTER key.

##  Threat Model
WhisperTLS is designed to protect against:

-   **Eavesdropping** (via TLS + Double Ratchet)    
-   **Man-in-the-middle attacks** (via mutual TLS + TOFU)    
-   **Traffic analysis** (via constant-rate padding)    
-   **IP address exposure** (via Tor onion services)
-   **Centralized metadata collection** (pure P2P)

It does **not** protect against:

-   Endpoint compromise (keyloggers, malware)
-   Global adversary with full Tor node control
-   Denial-of-service (onion service flooding)
-   User error in initial key verification

### Identity & Rotation

-   Onion addresses are intended to be **stable** but can be rotated.
-   TLS certificates default expiration time es **1 week** (configurable from 1 minute to 1 year).
-   To rotate identity you need to perform a new OOB exchange, this generate new keys/certificates/onion address.

### Limitations

- **No offline messaging** – both peers must be online simultaneously.
- **No group chats** – strictly 1:1 communication.
- **Tor dependency** – requires Tor running and stable.
- **No voice/video yet** – text-only in current implementation but it can be implemented with your help

## License

WhisperTLS is released under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.  
See `LICENSE` for details.

## Reporting Issues

Please open GitHub issues for bugs, questions, or suggestions.

## GPG

This repository contains GPG-signed commits and tags.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaVdJ1RYJKwYBBAHaRw8BAQdASE/KShAoYF9g5nbBP3v38n6uF8aPALH4tuaJ
vL/1hM20CndoaXNwZXJ0bHOIkAQTFggAOBYhBOQG3xHDp7pAu7ImO5UxRlR3p7ii
BQJpV0nVAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEJUxRlR3p7ii99EA
/Rg0fsH9MJm2OUVHzNBuvOk0wPAOvXMlFVohwTqJ8/PpAQDltFT5XTY1i37clUTA
mJsvAAwaBlh1AiCOmw/L/EB7A7g4BGlXSdUSCisGAQQBl1UBBQEBB0Dn1XZ8sC8s
9zBNyfEPNrecKvbNCWYSV/nlmqddYuB3BgMBCAeIeAQYFggAIBYhBOQG3xHDp7pA
u7ImO5UxRlR3p7iiBQJpV0nVAhsMAAoJEJUxRlR3p7iiRSAA/A4/Eeg8AmlPKT62
FftLPq2nooVr2rfcqzQqN2gpTJvUAPsH4aL4L4MCo6o+Ikr2BiIpgL0+w6XtiUVB
UgHSWQWACg==
=XSQe
-----END PGP PUBLIC KEY BLOCK-----
```

### Public Key Information

- **Fingerprint**: `E406 DF11 C3A7 BA40 BBB2  263B 9531 4654 77A7 B8A2`
- **Key File**: [.well-known/gpg-pubkey.asc](/.well-known/gpg-pubkey.asc)

### Verification Commands

```
git verify-commit <commit-hash>
```

## Donations

We have been working on this open-source project for several months and plan to continue its development. 
If you'd like to support us, donations can be sent to our Bitcoin address:

bc1qspet74ylm5txa2vzgfj84uysflzkckcdj385m4