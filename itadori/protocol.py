"""Wire format and crypto. Data plane: truncated HMAC (cheap). Control plane: Ed25519 signatures (unforgeable by insiders)."""
import hashlib, hmac, random, struct
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

HELLO, LSA, DATA, CTRL = 1, 2, 3, 4
ACCUSE, PREPREPARE, PREPARE, COMMIT = 1, 2, 3, 4
BCAST, MAC, SIG, MAX_FRAME = 0xFF, 8, 64, 255
HDR = struct.Struct('>BBBBHBB')  # type, origin, sender, next hop, seq, ttl, payload length

@dataclass
class Frame:
    type: int
    origin: int
    sender: int
    nexthop: int
    seq: int
    ttl: int
    payload: bytes = b''
    def copy(self, **kw):
        d = dict(self.__dict__); d.update(kw); return Frame(**d)

def _mac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()[:MAC]

def build(f, knet):
    body = HDR.pack(f.type, f.origin, f.sender, f.nexthop, f.seq & 0xFFFF, f.ttl, len(f.payload)) + f.payload
    out = body + _mac(knet, body)
    assert len(out) <= MAX_FRAME, 'frame exceeds LoRa payload limit'
    return out

def parse(buf, knet):
    if len(buf) < HDR.size + MAC: return None
    body, tag = buf[:-MAC], buf[-MAC:]
    if not hmac.compare_digest(_mac(knet, body), tag): return None
    t, o, s, n, q, ttl, pl = HDR.unpack_from(body)
    payload = body[HDR.size:]
    return Frame(t, o, s, n, q, ttl, payload) if len(payload) == pl else None

def e2e_tag(key, origin, seq, app):
    return _mac(key, bytes([origin]) + struct.pack('>H', seq & 0xFFFF) + app)

def _signed(ctype, body, origin, seq):
    return bytes([ctype]) + body + bytes([origin]) + struct.pack('>H', seq & 0xFFFF)

def sign(priv, ctype, body, origin, seq):
    return priv.sign(_signed(ctype, body, origin, seq))

def verify(pub, sig, ctype, body, origin, seq):
    try:
        pub.verify(sig, _signed(ctype, body, origin, seq)); return True
    except InvalidSignature:
        return False

class Provision:
    """Keys loaded onto nodes before deployment: network key, per-node end-to-end keys (also held by the gateway), signing keys."""
    def __init__(self, n, seed=0):
        r = random.Random(seed)
        key = lambda: bytes(r.getrandbits(8) for _ in range(16))
        self.knet = key()
        self.e2e = {i: key() for i in range(n)}
        self.priv = {i: ed25519.Ed25519PrivateKey.generate() for i in range(n)}
        self.pub = {i: k.public_key() for i, k in self.priv.items()}
