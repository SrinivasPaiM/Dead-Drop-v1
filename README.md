# P2P Dead Drop

## Overview

**P2P Dead Drop** is a simple, secure, and ephemeral peer-to-peer messaging and file transfer tool for local networks. It uses a "room" passphrase for automatic discovery and encrypted communication. Messages and files are deleted after being fetched or after a short expiry, ensuring privacy and minimal footprint.

## Features

- **Effortless LAN communication:** No setup, no central server, just run and send.
- **Ephemeral drops:** Each message or file is deleted after first fetch or expiry.
- **Automatic fetching:** Receivers auto-fetch new drops in their room—no manual token copying needed.
- **Strong encryption:** All payloads are encrypted using a passphrase-derived key (scrypt + Fernet).
- **Cross-platform:** Works on Windows, Linux, and macOS.

## How It Works

1. **Create a Room:**  
   Both sender and receiver use the same room passphrase to join a secure, private group.

2. **Send a Message or File:**  
   The sender creates a drop (message or file) in the room. The receiver automatically discovers and fetches it.

## Quick Start

### 1. Start the Receiver (Join a Room)

On any device in your LAN, run:

```sh
python p2p_dead_drop.py run --room <room_passphrase>
```

- Replace `<room_passphrase>` with your chosen passphrase.
- Leave this running. It will automatically fetch any new drops sent to the room.

### 2. Send a Message

On another device (or the same device), run:

```sh
python p2p_dead_drop.py send-msg --room <room_passphrase> --ttl 12 "Your message here"
```

- Use the same `<room_passphrase>`.
- `--ttl` is the time (in seconds) before the drop expires (default: 12s).
- The message will be auto-fetched and displayed by any receiver in the room.

### 3. Send a File

```sh
python p2p_dead_drop.py send-file <filepath> --room <room_passphrase> --ttl 300
```

- `<filepath>` is the path to your file.
- The file will be auto-fetched and saved by receivers in the room.

## Example

**Receiver:**
```sh
python p2p_dead_drop.py run --room secret123
```

**Sender:**
```sh
python p2p_dead_drop.py send-msg --room secret123 "Hello, team!"
```

**Result:**  
All receivers in the room instantly see the message. No manual steps, no token copying.

## Visual Demo: Phone to Laptop

Below is a demonstration of sending a message from a phone (using Termux) to a laptop, both connected to the same WiFi network.

### 1. **Message Sent from Phone (Termux)**

![mobile_msg](https://github.com/user-attachments/assets/bc141161-a012-43d0-8223-c1a34a3e6e7a)



### 2. **Message Received on Laptop**

![pc_pic](https://github.com/user-attachments/assets/29e909d8-0280-45e2-a3a8-f5df62aebbad)


- The phone uses [Termux](https://termux.com/) to run the Python script and send the message.
- The laptop runs the receiver and automatically displays the incoming message.

## Advanced

- You can still manually fetch a drop using the `fetch` command if needed.
- Use a strong room passphrase for privacy.
- Drops are deleted after being fetched or after TTL expiry.

## Why Dead Drop?

A "dead drop" is a secure, one-time exchange—like leaving a note in a hidden spot. This tool brings that concept to your LAN, with encryption and automatic cleanup.

## License

MIT License

---

**Effortless, secure, ephemeral communication—just join a room and send.**
