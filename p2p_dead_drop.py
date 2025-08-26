#!/usr/bin/env python3
"""
p2p_dead_drop.py - MVP peer-to-peer ephemeral "dead drop" over LAN.
- LAN discovery via UDP broadcast
- Direct fetch via TCP from sender
- Ephemeral: drop is deleted after first successful fetch or TTL expiry
- Encrypted payload using passphrase-derived key (scrypt + Fernet)
Usage examples:
  python p2p_dead_drop.py run --room myroom
  python p2p_dead_drop.py send-msg --to 192.168.1.23 --room myroom --ttl 120 "hello there"
  python p2p_dead_drop.py send-file --to 192.168.1.23 --room myroom --ttl 300 /path/to/file.pdf
  # On receiver side, watch offers in 'run' output and then:
  python p2p_dead_drop.py fetch --from 192.168.1.10 --token <token> --room myroom --out out.bin
"""
import argparse
import asyncio
import base64
import json
import os
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet, InvalidToken
except Exception as e:
    print("Missing dependency: cryptography. Install with: pip install cryptography")
    raise

UDP_PORT = 48555
TCP_PORT_DEFAULT = 48556
BCAST_INTERVAL = 5.0
OFFER_TTL_GRACE = 2.0  # seconds allowed beyond TTL for late fetch


def get_local_ip() -> str:
    # Find local IP by opening a UDP socket to a non-routable address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(passphrase.encode('utf-8'))
    return base64.urlsafe_b64encode(key)


def encrypt_bytes(passphrase: str, plaintext: bytes) -> bytes:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    f = Fernet(key)
    token = f.encrypt(plaintext)
    return salt + token


def decrypt_bytes(passphrase: str, blob: bytes) -> bytes:
    salt, token = blob[:16], blob[16:]
    key = derive_key(passphrase, salt)
    f = Fernet(key)
    return f.decrypt(token)


def room_hash(passphrase: str) -> str:
    # Short, non-cryptographic room identifier for filtering
    import hashlib
    return hashlib.sha256(("room:" + passphrase).encode()).hexdigest()[:12]


@dataclass
class Drop:
    token: str
    payload: bytes
    kind: str  # 'msg' or 'file'
    name: str  # label or filename
    expires_at: float
    fetched: bool = False


class DropStore:
    def __init__(self):
        self._drops: Dict[str, Drop] = {}
        self._lock = threading.Lock()

    def add(self, drop: Drop):
        with self._lock:
            self._drops[drop.token] = drop

    def take(self, token: str) -> Optional[Drop]:
        with self._lock:
            d = self._drops.get(token)
            if not d:
                return None
            # enforce TTL and one-time fetch
            now = time.time()
            if d.fetched or now > d.expires_at + OFFER_TTL_GRACE:
                # delete if expired/used
                self._drops.pop(token, None)
                return None
            d.fetched = True
            self._drops.pop(token, None)
            return d

    def reap(self):
        with self._lock:
            now = time.time()
            to_del = [t for t, d in self._drops.items() if now > d.expires_at + OFFER_TTL_GRACE or d.fetched]
            for t in to_del:
                self._drops.pop(t, None)


class UDPBroadcaster(threading.Thread):
    def __init__(self, room: str, tcp_port: int, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.room = room
        self.tcp_port = tcp_port
        self.stop_event = stop_event
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def run(self):
        ip = get_local_ip()
        msg = json.dumps({"t": "HELLO", "room": self.room, "ip": ip, "port": self.tcp_port}).encode()
        while not self.stop_event.is_set():
            try:
                self.sock.sendto(msg, ('255.255.255.255', UDP_PORT))
            except Exception:
                pass
            self.stop_event.wait(BCAST_INTERVAL)


class UDPListener(threading.Thread):
    def __init__(self, room: str, offers: Dict[str, dict], stop_event: threading.Event):
        super().__init__(daemon=True)
        self.room = room
        self.offers = offers  # shared dict of offer_id -> offer
        self.stop_event = stop_event
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', UDP_PORT))

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.sock.settimeout(1.0)
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                continue
            try:
                msg = json.loads(data.decode())
            except Exception:
                continue
            if msg.get("room") != self.room:
                continue
            if msg.get("t") == "HELLO":
                # Could track peers here
                continue
            if msg.get("t") == "OFFER":
                # record offer for display
                offer_id = msg.get("id")
                self.offers[offer_id] = {**msg, "from": addr[0]}


class TCPServer(threading.Thread):
    def __init__(self, store: DropStore, tcp_port: int, passphrase: str, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.store = store
        self.tcp_port = tcp_port
        self.passphrase = passphrase
        self.stop_event = stop_event

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('', self.tcp_port))
        srv.listen(5)
        srv.settimeout(1.0)
        while not self.stop_event.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def handle_client(self, conn: socket.socket, addr):
        try:
            # Simple line-based protocol: first line is JSON request
            f = conn.makefile('rwb')
            line = f.readline().strip()
            try:
                req = json.loads(line.decode())
            except Exception:
                f.write(b'{"ok": false, "err": "badjson"}\n')
                f.flush()
                return
            if req.get("op") != "fetch":
                f.write(b'{"ok": false, "err": "badop"}\n')
                f.flush()
                return
            token = req.get("token", "")
            drop = self.store.take(token)
            if not drop:
                f.write(b'{"ok": false, "err": "notfound"}\n')
                f.flush()
                return
            # Provide metadata then payload length and payload
            meta = {"ok": True, "kind": drop.kind, "name": drop.name}
            f.write((json.dumps(meta) + "\n").encode())
            f.flush()
            # write 8-byte length prefix then bytes
            payload = drop.payload
            f.write(struct.pack("!Q", len(payload)))
            f.flush()
            f.write(payload)
            f.flush()
        finally:
            try:
                conn.close()
            except Exception:
                pass


def broadcast_offer(room: str, offer: dict):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    data = json.dumps({**offer, "room": room}).encode()
    try:
        sock.sendto(data, ('255.255.255.255', UDP_PORT))
    except Exception:
        pass


def cmd_run(args):
    room = room_hash(args.room)
    store = DropStore()
    stop_event = threading.Event()

    offers = {}
    udp_listener = UDPListener(room, offers, stop_event)
    udp_listener.start()

    tcp_srv = TCPServer(store, args.tcp_port, args.room, stop_event)
    tcp_srv.start()

    bcast = UDPBroadcaster(room, args.tcp_port, stop_event)
    bcast.start()

    print(f"[node] running: room={args.room} ({room}), tcp_port={args.tcp_port}, ip={get_local_ip()}")
    print("[node] waiting for offers... (press Ctrl+C to exit)")
    try:
        while True:
            # Reap expired drops
            store.reap()
            # Show known offers
            if offers:
                print("\n[offers]")
                for oid, off in list(offers.items()):
                    exp_in = int(off['expires_at'] - time.time())
                    if exp_in <= 0:
                        offers.pop(oid, None)
                        continue
                    print(f"  token={off['id'][:8]}.. kind={off['kind']} name={off['name']} from={off['from']}:{off['port']} ttl={exp_in}s")
            time.sleep(2.0)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(0.5)


def cmd_send_msg(args):
    token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    payload = encrypt_bytes(args.room, args.message.encode('utf-8'))
    drop = Drop(token=token, payload=payload, kind='msg', name='message', expires_at=time.time() + args.ttl)
    # add to local store and serve it
    room = room_hash(args.room)
    store = DropStore()
    stop_event = threading.Event()
    tcp_srv = TCPServer(store, args.tcp_port, args.room, stop_event)
    tcp_srv.start()
    store.add(drop)
    offer = {
        "t": "OFFER",
        "id": token,
        "kind": "msg",
        "name": "message",
        "port": args.tcp_port,
        "expires_at": drop.expires_at,
    }
    broadcast_offer(room, offer)
    ip = get_local_ip()
    print(f"[offer] msg ready: token={token} fetch=from {ip}:{args.tcp_port} within {args.ttl}s")
    try:
        # wait until fetched or expired
        while True:
            time.sleep(1.0)
            if time.time() > drop.expires_at + OFFER_TTL_GRACE:
                print("[offer] expired; shutting down")
                break
            # check if fetched
            # no direct signal; but we can test store empty
            if store.take(token) is None:
                # either fetched or expired removed; check expiry
                if time.time() <= drop.expires_at + 1.0:
                    print("[offer] fetched; shutting down")
                break
    finally:
        stop_event.set()
        time.sleep(0.2)


def cmd_send_file(args):
    path = args.filepath
    if not os.path.isfile(path):
        print("file not found:", path)
        sys.exit(1)
    with open(path, 'rb') as f:
        data = f.read()
    token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    payload = encrypt_bytes(args.room, data)
    name = os.path.basename(path)
    drop = Drop(token=token, payload=payload, kind='file', name=name, expires_at=time.time() + args.ttl)
    room = room_hash(args.room)
    store = DropStore()
    stop_event = threading.Event()
    tcp_srv = TCPServer(store, args.tcp_port, args.room, stop_event)
    tcp_srv.start()
    store.add(drop)
    offer = {
        "t": "OFFER",
        "id": token,
        "kind": "file",
        "name": name,
        "port": args.tcp_port,
        "expires_at": drop.expires_at,
    }
    broadcast_offer(room, offer)
    ip = get_local_ip()
    print(f"[offer] file ready: {name} ({len(data)} bytes) token={token} fetch=from {ip}:{args.tcp_port} within {args.ttl}s")
    try:
        while True:
            time.sleep(1.0)
            if time.time() > drop.expires_at + OFFER_TTL_GRACE:
                print("[offer] expired; shutting down")
                break
            if store.take(token) is None:
                if time.time() <= drop.expires_at + 1.0:
                    print("[offer] fetched; shutting down")
                break
    finally:
        stop_event.set()
        time.sleep(0.2)


def cmd_fetch(args):
    # connect to sender TCP and request token
    addr = (args.from_ip, args.port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(5.0)
        s.connect(addr)
        f = s.makefile('rwb')
        req = {"op": "fetch", "token": args.token}
        f.write((json.dumps(req) + "\n").encode())
        f.flush()
        line = f.readline().strip()
        try:
            resp = json.loads(line.decode())
        except Exception:
            print("[fetch] bad response")
            return 1
        if not resp.get("ok"):
            print("[fetch] error:", resp.get("err"))
            return 1
        kind = resp.get("kind")
        name = resp.get("name")
        # read length and payload
        ln = f.read(8)
        if len(ln) != 8:
            print("[fetch] failed to read length")
            return 1
        (nbytes,) = struct.unpack("!Q", ln)
        blob = b''
        remaining = nbytes
        while remaining > 0:
            chunk = f.read(min(65536, remaining))
            if not chunk:
                break
            blob += chunk
            remaining -= len(chunk)
        # decrypt
        try:
            data = decrypt_bytes(args.room, blob)
        except InvalidToken:
            print("[fetch] decryption failed; wrong room passphrase?")
            return 1
        # output
        outpath = args.out or (name if kind == 'file' else None)
        if outpath:
            with open(outpath, 'wb') as g:
                g.write(data)
            print(f"[fetch] saved to {outpath}")
        else:
            # print message
            try:
                print("[msg]", data.decode('utf-8', errors='replace'))
            except Exception:
                print("[msg] (binary data) len=", len(data))
        return 0
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description="P2P Dead Drop (ephemeral, encrypted, LAN)")
    sub = ap.add_subparsers(dest='cmd', required=True)

    ap_run = sub.add_parser('run', help='run node, listen for offers')
    ap_run.add_argument('--room', required=True, help='shared room passphrase')
    ap_run.add_argument('--tcp-port', type=int, default=TCP_PORT_DEFAULT)
    ap_run.set_defaults(func=cmd_run)

    ap_sm = sub.add_parser('send-msg', help='send an ephemeral encrypted message')
    ap_sm.add_argument('message', help='message text')
    ap_sm.add_argument('--room', required=True, help='shared room passphrase')
    ap_sm.add_argument('--ttl', type=int, default=120, help='seconds before drop expires')
    ap_sm.add_argument('--tcp-port', type=int, default=TCP_PORT_DEFAULT)
    ap_sm.set_defaults(func=cmd_send_msg)

    ap_sf = sub.add_parser('send-file', help='send an ephemeral encrypted file')
    ap_sf.add_argument('filepath', help='path to file')
    ap_sf.add_argument('--room', required=True, help='shared room passphrase')
    ap_sf.add_argument('--ttl', type=int, default=300)
    ap_sf.add_argument('--tcp-port', type=int, default=TCP_PORT_DEFAULT)
    ap_sf.set_defaults(func=cmd_send_file)

    ap_fetch = sub.add_parser('fetch', help='fetch a drop from a peer')
    ap_fetch.add_argument('--from', dest='from_ip', required=True, help='peer IP to fetch from')
    ap_fetch.add_argument('--port', type=int, default=TCP_PORT_DEFAULT)
    ap_fetch.add_argument('--token', required=True, help='drop token')
    ap_fetch.add_argument('--room', required=True, help='shared room passphrase')
    ap_fetch.add_argument('--out', help='output path (optional)')
    ap_fetch.set_defaults(func=cmd_fetch)

    args = ap.parse_args()
    rc = args.func(args)
    if isinstance(rc, int):
        sys.exit(rc)


if __name__ == '__main__':
    main()
