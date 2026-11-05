#!/usr/bin/env python3
"""模拟扫描器 / 没装 mod 的机器人，检查 TrustedServer 第一阶段的防护效果（只用标准库）。

用法：
  python3 tools/probe_server.py status  [host] [port]   # 现代服务器列表 Ping：玩家样本应为空
  python3 tools/probe_server.py legacy  [host] [port]   # 旧版（1.6 格式）Ping
  python3 tools/probe_server.py login   [host] [port]   # 离线模式下模拟机器人登录：应被统一拒绝文本断开
  python3 tools/probe_server.py flood   [host] [port]   # 连续 Ping，观察何时被限流

默认 host=127.0.0.1，port=25565。login 需要服务器为离线模式（online-mode=false）才能走到 mod 的握手。
"""
import json
import socket
import struct
import sys
import zlib

PROTOCOL_1_20_1 = 763


def varint(value):
    out = bytearray()
    value &= 0xFFFFFFFF
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_varint_from(read):
    value = 0
    for i in range(5):
        b = read(1)[0]
        value |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return value
    raise ValueError("VarInt too long")


def string(s):
    data = s.encode("utf-8")
    return varint(len(data)) + data


class Conn:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.threshold = -1

    def recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("connection closed by server")
            buf += chunk
        return buf

    def send(self, packet_id, body=b""):
        data = varint(packet_id) + body
        if self.threshold >= 0:
            data = varint(0) + data  # 不压缩
        self.sock.sendall(varint(len(data)) + data)

    def recv(self):
        length = read_varint_from(self.recv_exact)
        data = self.recv_exact(length)
        if self.threshold >= 0:
            pos = 0
            inner_len = 0
            shift = 0
            while True:
                b = data[pos]
                pos += 1
                inner_len |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            data = data[pos:] if inner_len == 0 else zlib.decompress(data[pos:])
        pos = [0]

        def read(n):
            chunk = data[pos[0]:pos[0] + n]
            pos[0] += n
            return chunk

        packet_id = read_varint_from(read)
        return packet_id, data[pos[0]:]


def handshake(conn, host, port, next_state):
    conn.send(0x00, varint(PROTOCOL_1_20_1) + string(host) + struct.pack(">H", port) + varint(next_state))


def status(host, port):
    conn = Conn(host, port)
    handshake(conn, host, port, 1)
    conn.send(0x00)
    _, body = conn.recv()
    pos = [0]

    def read(n):
        chunk = body[pos[0]:pos[0] + n]
        pos[0] += n
        return chunk

    length = read_varint_from(read)
    info = json.loads(body[pos[0]:pos[0] + length].decode("utf-8"))
    players = info.get("players", {})
    print("online:", players.get("online"), "max:", players.get("max"))
    print("sample:", players.get("sample", []), "(应为空)")
    return info


def legacy(host, port):
    sock = socket.create_connection((host, port), timeout=10)
    sock.sendall(b"\xfe\x01")
    data = sock.recv(4096)
    sock.close()
    if not data or data[0] != 0xFF:
        print("unexpected legacy reply:", data[:16])
        return
    text = data[3:].decode("utf-16-be").split("\x00")
    print("legacy reply fields:", text)
    if len(text) >= 6:
        print("online:", text[4], "max:", text[5])


def login(host, port, name="ProbeBot"):
    conn = Conn(host, port)
    handshake(conn, host, port, 2)
    conn.send(0x00, string(name) + b"\x00")  # Login Start：名字 + 不带 UUID
    while True:
        try:
            packet_id, body = conn.recv()
        except EOFError:
            print("server closed the connection")
            return
        if packet_id == 0x03:  # Set Compression
            pos = [0]
            conn.threshold = read_varint_from(lambda n: (body[pos[0]:pos[0] + n], pos.__setitem__(0, pos[0] + n))[0])
            print("compression threshold:", conn.threshold)
        elif packet_id == 0x04:  # Login Plugin Request
            pos = [0]

            def read(n):
                chunk = body[pos[0]:pos[0] + n]
                pos[0] += n
                return chunk

            message_id = read_varint_from(read)
            channel_len = read_varint_from(read)
            channel = read(channel_len).decode("utf-8")
            print("login plugin request on", channel, "-> answering 'not understood' like a bot")
            conn.send(0x02, varint(message_id) + b"\x00")
        elif packet_id == 0x00:  # Disconnect
            pos = [0]
            reason_len = read_varint_from(lambda n: (body[pos[0]:pos[0] + n], pos.__setitem__(0, pos[0] + n))[0])
            print("disconnected with:", body[pos[0]:pos[0] + reason_len].decode("utf-8"))
            return
        elif packet_id == 0x01:
            print("server asked for encryption: online-mode is on, bots stop at Mojang authentication")
            return
        elif packet_id == 0x02:
            print("LOGIN SUCCESS — the bot got in (this should not happen)")
            return
        else:
            print("packet", hex(packet_id))


def flood(host, port, count=40):
    for i in range(1, count + 1):
        try:
            conn = Conn(host, port)
            handshake(conn, host, port, 1)
            conn.send(0x00)
            conn.recv()
            conn.sock.close()
        except (EOFError, OSError) as e:
            print(f"ping #{i}: refused ({e.__class__.__name__}) — rate limit reached")
            return
    print(f"all {count} pings answered")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "status"
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 25565
    {"status": status, "legacy": legacy, "login": login, "flood": flood}[mode](host, port)
