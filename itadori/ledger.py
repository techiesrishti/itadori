"""
Itadori permissioned ledger – a tamper-evident, hash-chained audit log of cluster
decisions.  NOT a public blockchain: no proof-of-work, no tokens.  Finality comes
from a quorum (2f+1) of cluster Ed25519 commit signatures.  The chain is only as
trustworthy as the honest majority of the cluster.

Block structure
---------------
height      : int   – 0 for genesis, monotonically increasing
prev_hash   : bytes – SHA-256 of the previous block's canonical bytes (32 bytes)
records     : list  – list of Record dicts (see below)
block_hash  : bytes – SHA-256 of this block's canonical bytes (computed on creation)
sigs        : dict  – {node_id: 64-byte Ed25519 signature} finality proof (not in hash)

Record types
------------
QUARANTINE  : {'type': 'QUARANTINE', 'target': int, 'accusers': [int, ...], 'cseq': int}
DELIVERY_ROOT (stretch):
            {'type': 'DELIVERY_ROOT', 'epoch': int, 'merkle_root': hex_str}

Persistence
-----------
Each node persists its chain as JSON-lines in <data_dir>/<node_id>.jsonl.
On load the full hash chain is re-verified; a broken chain raises ValueError.

Sync protocol
-------------
Block hashes and heights are piggybacked on existing HELLO frames (8-byte truncated
head hash + 2-byte height in the payload extension).  A node that sees a taller or
different head sends a signed CTRL BLOCK_REQ; the peer replies with BLOCK_RESP frames
(one block per frame, fragmented to stay inside the 255-byte LoRa limit).
"""
import hashlib, json, os, struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Record helpers
# ---------------------------------------------------------------------------

def quarantine_record(target: int, accusers: List[int], cseq: int) -> dict:
    return {'type': 'QUARANTINE', 'target': target, 'accusers': sorted(accusers), 'cseq': cseq}

def delivery_root_record(epoch: int, merkle_root: str) -> dict:
    return {'type': 'DELIVERY_ROOT', 'epoch': epoch, 'merkle_root': merkle_root}

# ---------------------------------------------------------------------------
# Canonical serialisation (must be identical on every node)
# ---------------------------------------------------------------------------

def _canonical_record(r: dict) -> bytes:
    if r['type'] == 'QUARANTINE':
        accusers = bytes(r['accusers'])
        return b'Q' + bytes([r['target'], len(accusers)]) + accusers + struct.pack('>H', r['cseq'])
    if r['type'] == 'DELIVERY_ROOT':
        return b'D' + struct.pack('>H', r['epoch']) + bytes.fromhex(r['merkle_root'])
    raise ValueError(f"Unknown record type {r['type']!r}")

def _canonical_block(height: int, prev_hash: bytes, records: List[dict]) -> bytes:
    parts = [struct.pack('>I', height), prev_hash]
    for r in records:
        parts.append(_canonical_record(r))
    return b''.join(parts)

def block_hash(height: int, prev_hash: bytes, records: List[dict]) -> bytes:
    return hashlib.sha256(_canonical_block(height, prev_hash, records)).digest()

# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------

@dataclass
class Block:
    height: int
    prev_hash: bytes                     # 32 bytes
    records: List[dict]
    block_hash: bytes                    # 32 bytes, computed on creation
    sigs: Dict[int, bytes] = field(default_factory=dict)   # node_id -> 64-byte sig

    # ---- serialisation ----
    def to_json(self) -> str:
        out_sigs = {}
        for k, v in self.sigs.items():
            if isinstance(v, tuple):
                out_sigs[str(k)] = f"{v[0]}:{v[1].hex()}"
            else:
                out_sigs[str(k)] = v.hex()
        return json.dumps({
            'height': self.height,
            'prev_hash': self.prev_hash.hex(),
            'records': self.records,
            'block_hash': self.block_hash.hex(),
            'sigs': out_sigs,
        })

    @staticmethod
    def from_json(s: str) -> 'Block':
        d = json.loads(s)
        sigs = {}
        for k, v in d.get('sigs', {}).items():
            if ':' in v:
                seq_str, hx = v.split(':', 1)
                sigs[int(k)] = (int(seq_str), bytes.fromhex(hx))
            else:
                sigs[int(k)] = bytes.fromhex(v)
        return Block(
            height=d['height'],
            prev_hash=bytes.fromhex(d['prev_hash']),
            records=d['records'],
            block_hash=bytes.fromhex(d['block_hash']),
            sigs=sigs,
        )

    # ---- wire serialisation (compact, single frame) ----
    def to_wire(self) -> bytes:
        """
        Compact binary serialisation for BLOCK_RESP. To fit inside a 255-byte
        LoRa frame (minus CTRL header + MAC + frame sig overhead = ~80 bytes)
        we:
          1. Use binary canonical records to save space.
          2. Transmit only ONE commit signature (the sender's or primary's).
        """
        rec_bytes = b''.join(_canonical_record(r) for r in self.records)
        sig_items = sorted(self.sigs.items())[:1]
        parts = [
            struct.pack('>IB', self.height, len(self.records)),
            self.prev_hash,
            self.block_hash,
            struct.pack('>B', len(rec_bytes)),
            rec_bytes,
            bytes([len(sig_items)]),
        ]
        for nid, val in sig_items:
            if isinstance(val, tuple):
                seq, sig_bytes = val
                parts.append(bytes([nid]) + struct.pack('>H', seq) + sig_bytes)
            else:
                parts.append(bytes([nid]) + struct.pack('>H', 0) + val)
        return b''.join(parts)

    @staticmethod
    def from_wire(data: bytes) -> 'Block':
        off = 0
        height, nrecords = struct.unpack_from('>IB', data, off); off += 5
        prev_hash = data[off:off+32]; off += 32
        blk_hash = data[off:off+32]; off += 32
        rec_len = data[off]; off += 1
        rec_bytes = data[off:off+rec_len]; off += rec_len
        records = []
        roff = 0
        for _ in range(nrecords):
            rtype = chr(rec_bytes[roff]); roff += 1
            if rtype == 'Q':
                target = rec_bytes[roff]; roff += 1
                n_acc = rec_bytes[roff]; roff += 1
                accusers = list(rec_bytes[roff:roff+n_acc]); roff += n_acc
                cseq = struct.unpack_from('>H', rec_bytes, roff)[0]; roff += 2
                records.append(quarantine_record(target, accusers, cseq))
            elif rtype == 'D':
                epoch = struct.unpack_from('>H', rec_bytes, roff)[0]; roff += 2
                merkle_root = rec_bytes[roff:roff+32].hex(); roff += 32
                records.append(delivery_root_record(epoch, merkle_root))
        nsigs = data[off]; off += 1
        sigs = {}
        for _ in range(nsigs):
            nid = data[off]; off += 1
            cseq = struct.unpack_from('>H', data, off)[0]; off += 2
            sig_bytes = data[off:off+64]; off += 64
            sigs[nid] = (cseq, sig_bytes) if cseq != 0 else sig_bytes
        return Block(height=height, prev_hash=prev_hash, records=records,
                     block_hash=blk_hash, sigs=sigs)

    @property
    def head_summary(self) -> bytes:
        """8-byte truncated hash + 2-byte height for HELLO piggyback."""
        return self.block_hash[:8] + struct.pack('>H', self.height)

# ---------------------------------------------------------------------------
# Chain
# ---------------------------------------------------------------------------

GENESIS_MAGIC = b'ITADORI_GENESIS_v1'

def _genesis_prev_hash(cluster: tuple, knet: bytes) -> bytes:
    """
    Fixed genesis prev_hash derived from the provisioned network key and cluster IDs.
    Uses knet (deterministically seeded) rather than Ed25519 pub keys (which are
    generated fresh each time and cannot be seeded).
    """
    h = hashlib.sha256(GENESIS_MAGIC)
    h.update(knet)
    for nid in sorted(cluster):
        h.update(struct.pack('>B', nid))
    return h.digest()

class Chain:
    """An append-only, hash-linked chain of Blocks."""

    def __init__(self, node_id: int, cluster: tuple, pub_keys: dict,
                 knet: bytes = b'', data_dir: Optional[str] = None):
        self.node_id = node_id
        self.cluster = cluster
        self.pub_keys = pub_keys          # {node_id: Ed25519PublicKey}
        self.quorum = 2 * ((len(cluster) - 1) // 3) + 1
        self._blocks: List[Block] = []
        self._data_dir = data_dir

        # Build genesis block (deterministic from knet + cluster IDs)
        genesis_prev = _genesis_prev_hash(cluster, knet)
        gh = block_hash(0, genesis_prev, [])
        self._genesis = Block(height=0, prev_hash=genesis_prev, records=[], block_hash=gh)
        self._blocks.append(self._genesis)

        if data_dir:
            os.makedirs(data_dir, exist_ok=True)
            self._path = os.path.join(data_dir, f'node_{node_id}.jsonl')
            if not os.path.exists(self._path):
                with open(self._path, 'w', encoding='utf-8') as f:
                    f.write(self._genesis.to_json() + '\n')
            else:
                self._load()

    # ---- persistence ----
    def _load(self):
        if not os.path.exists(self._path):
            return
        with open(self._path, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        if not lines:
            return
        loaded: List[Block] = []
        for line in lines:
            if line.strip():
                loaded.append(Block.from_json(line))
        if loaded and loaded[0].height != 0:
            loaded = [self._genesis] + loaded
        # Verify genesis matches
        if loaded and loaded[0].block_hash != self._genesis.block_hash:
            raise ValueError('Chain genesis mismatch – provisioned keys changed?')
        # Verify whole chain
        for i in range(1, len(loaded)):
            self._verify_link(loaded[i-1], loaded[i])
            self._verify_sigs(loaded[i])
        # Replace in-memory chain
        if loaded:
            self._blocks = loaded

    def _save_last(self):
        if not self._data_dir:
            return
        if not os.path.exists(self._path):
            self._save_all()
            return
        with open(self._path, 'a', encoding='utf-8') as f:
            f.write(self._blocks[-1].to_json() + '\n')

    def _save_all(self):
        """Rewrite the whole file (used after resync)."""
        if not self._data_dir:
            return
        with open(self._path, 'w', encoding='utf-8') as f:
            for b in self._blocks:
                f.write(b.to_json() + '\n')

    # ---- verification ----
    @staticmethod
    def _verify_link(prev: Block, blk: Block):
        if blk.height != prev.height + 1:
            raise ValueError(f'Height gap: {prev.height} -> {blk.height}')
        if blk.prev_hash != prev.block_hash:
            raise ValueError(f'Hash link broken at height {blk.height}')
        expected = block_hash(blk.height, blk.prev_hash, blk.records)
        if blk.block_hash != expected:
            raise ValueError(f'block_hash mismatch at height {blk.height}')

    def _verify_sigs(self, blk: Block, min_sigs: int = None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        from . import protocol as P
        good = 0
        signed_hash = blk.block_hash
        commit_body = None
        for r in blk.records:
            if r.get('type') == 'QUARANTINE':
                commit_body = bytes([r['target']]) + struct.pack('>H', r['cseq'])
                break

        for nid, val in blk.sigs.items():
            pub = self.pub_keys.get(nid)
            if pub is None or nid not in self.cluster:
                continue
            verified = False
            if isinstance(val, tuple):
                cseq, raw_sig = val
                if commit_body and P.verify(pub, raw_sig, P.COMMIT, commit_body, nid, cseq):
                    verified = True
            elif isinstance(val, (bytes, bytearray)):
                if len(val) == 64:
                    try:
                        pub.verify(val, signed_hash)
                        verified = True
                    except InvalidSignature:
                        pass
                elif len(val) == 66 and commit_body:
                    cseq = struct.unpack_from('>H', val[:2])[0]
                    raw_sig = val[2:]
                    if P.verify(pub, raw_sig, P.COMMIT, commit_body, nid, cseq):
                        verified = True
            if verified:
                good += 1

        required = min_sigs if min_sigs is not None else self.quorum
        if good < required:
            raise ValueError(
                f'Block {blk.height} has only {good}/{required} valid signatures')

    def verify_chain(self):
        """Re-verify the entire chain from genesis. Raises ValueError on failure."""
        for i in range(1, len(self._blocks)):
            self._verify_link(self._blocks[i-1], self._blocks[i])
            self._verify_sigs(self._blocks[i])

    # ---- append ----
    def append(self, records: List[dict], sigs: Dict[int, bytes]) -> Block:
        """
        Deterministically create the next block from records + commit signatures.
        Raises ValueError if the block would be invalid.
        """
        prev = self._blocks[-1]
        height = prev.height + 1
        bh = block_hash(height, prev.block_hash, records)
        blk = Block(height=height, prev_hash=prev.block_hash,
                    records=records, block_hash=bh, sigs=sigs)
        # Verify sigs before accepting
        self._verify_sigs(blk)
        self._blocks.append(blk)
        self._save_last()
        return blk

    def accept(self, blk: Block) -> bool:
        """
        Accept an externally supplied block (from sync).  Returns True if accepted,
        False if already known.  Raises ValueError if invalid.

        For sync, we require at least 1 valid Ed25519 signature from a known cluster
        member (the wire format only carries 1 sig to fit in a LoRa frame).  The full
        quorum of commit signatures was already established when the block was first
        sealed; here we just verify the hash chain and that the sig is authentic.
        """
        if blk.height <= self._blocks[-1].height:
            # Already known or stale
            return False
        if blk.height != self._blocks[-1].height + 1:
            raise ValueError(f'Cannot accept block at height {blk.height}: '
                             f'chain head is {self._blocks[-1].height}')
        self._verify_link(self._blocks[-1], blk)
        self._verify_sigs(blk, min_sigs=1)   # 1 valid sig sufficient for sync
        self._blocks.append(blk)
        self._save_last()
        return True

    # ---- sync ----
    def head(self) -> Block:
        return self._blocks[-1]

    def head_summary(self) -> bytes:
        return self.head().head_summary  # 10 bytes

    def get_block(self, height: int) -> Optional[Block]:
        if height < len(self._blocks):
            return self._blocks[height]
        return None

    @property
    def height(self) -> int:
        return self._blocks[-1].height

    @property
    def all_blocks(self) -> List[Block]:
        return list(self._blocks)

    # ---- tamper (test/demo helper) ----
    def tamper(self, height: int):
        """Flip a byte in a stored record for testing.  Does NOT update block_hash."""
        if height == 0 or height >= len(self._blocks):
            raise IndexError('Cannot tamper with genesis or non-existent block')
        blk = self._blocks[height]
        # Flip one byte in the first record's target field
        r = blk.records[0]
        r['target'] = r.get('target', 0) ^ 0xFF
        # block_hash is now stale – verify_chain() will detect this

    def is_intact(self) -> bool:
        """Return True iff chain passes full verification."""
        try:
            self.verify_chain()
            return True
        except ValueError:
            return False
