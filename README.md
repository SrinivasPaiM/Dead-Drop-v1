# P2P Dead Drop

## What is a Dead Drop?

A "dead drop" is a method of exchanging information between parties using a secret location or mechanism, without direct contact. In digital terms, this script allows you to send encrypted, ephemeral messages or files over a local network (LAN) without persistent storage or central servers. The drop is deleted after it is fetched once or after a time-to-live (TTL) expires.

## Features

- Peer-to-peer communication over LAN
- Ephemeral: drops are deleted after first fetch or TTL expiry
- Encrypted payloads using a passphrase-derived key (scrypt + Fernet)
- LAN discovery via UDP broadcast
- Direct fetch via TCP from sender

## Usage Overview

### 1. **Receiver (Listener) Setup**

The receiver listens for offers (messages/files) in a shared room.

```sh
python p2p_dead_drop.py run --room <room_passphrase>
```

- Replace `<room_passphrase>` with your chosen passphrase.
- Leave this running. It will display offers when a sender broadcasts them.

### 2. **Sender: Send a Message**

The sender creates and serves a message drop.

```sh
python p2p_dead_drop.py send-msg --room <room_passphrase> --ttl <seconds> "your message here"
```

- Use the same `<room_passphrase>` as the receiver.
- `--ttl` is the time (in seconds) before the drop expires.
- The sender must keep this process running until the message is fetched.

### 3. **Sender: Send a File**

The sender creates and serves a file drop.

```sh
python p2p_dead_drop.py send-file <filepath> --room <room_passphrase> --ttl <seconds>
```

- `<filepath>` is the path to the file you want to send.
- Use the same `<room_passphrase>` as the receiver.
- The sender must keep this process running until the file is fetched.

### 4. **Receiver: Fetch the Drop**

When an offer appears, note the token and sender IP. Fetch the drop with:

```sh
python p2p_dead_drop.py fetch --from <sender_ip> --token <token> --room <room_passphrase>
```

- `<sender_ip>` is the IP address shown in the offer.
- `<token>` is the full token string from the offer.
- The message will be printed to the terminal, or the file will be saved.

## Example Workflow

1. **Receiver:**  
   ```
   python p2p_dead_drop.py run --room myroom
   ```
2. **Sender:**  
   ```
   python p2p_dead_drop.py send-msg --room myroom --ttl 120 "hello there"
   ```
3. **Receiver:**  
   Wait for the offer, then:
   ```
   python p2p_dead_drop.py fetch --from <sender_ip> --token <token> --room myroom
   ```

## Notes

- Both sender and receiver must be on the same LAN/subnet and use the same room passphrase.
- The sender process must remain running until the drop is fetched.
- Drops are deleted after being fetched once or after TTL expiry.
- If you see connection errors, ensure both devices are on the same network and firewalls allow UDP/TCP traffic.

## Security

- All payloads are encrypted using a key derived from the room passphrase.
- Choose a strong passphrase for privacy.

## License

MIT License
