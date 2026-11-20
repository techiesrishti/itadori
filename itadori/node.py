"""One Itadori node: hello beacons, link-state routing, watchdog, signed accusations and PBFT-style quarantine consensus.
All timings are in 'protocol seconds'; real time = protocol seconds * cfg.scale (use scale < 1 to run faster than real time)."""
import asyncio, hashlib, hmac, random, struct, time
from collections import defaultdict
from dataclasses import dataclass
from . import protocol as P
from .lora import airtime
from .ledger import Chain, quarantine_record

@dataclass
class Config:
    mode: str = 'itadori'          # 'plain' = hop-count mesh that trusts everyone, 'itadori' = quality routing + trust + consensus
    scale: float = 0.04
    hello: float = 5.0
    lsa: float = 15.0
    data: float = 8.0
    warm: float = 25.0
    gw: int = 0
    cluster: tuple = (0, 1, 3, 6)  # consensus cluster, first member is the primary; 4 members tolerate f=1
    base_port: int = 20000
    seed: int = 1
    ledger_dir: str = None         # directory for per-node ledger persistence; None = in-memory only

class Node(asyncio.DatagramProtocol):
    def __init__(self, nid, cfg, prov):
        self.id, self.cfg, self.prov, self.scale = nid, cfg, prov, cfg.scale
        self.itadori = cfg.mode == 'itadori'
        self.rng = random.Random(nid * 977 + cfg.seed)
        self.hello_seq = self.lsa_seq = self.cseq = self.dseq = self.n = 0
        self.hist, self.lsdb, self.seen, self.cseen, self.pending, self.heard = {}, {}, set(), set(), {}, {}
        self.quarantined, self.accusers, self.last_accuse = set(), defaultdict(set), {}
        self.pp, self.voted, self.proposed, self.sent_commit = set(), set(), set(), set()
        self.prepares, self.commits = defaultdict(set), defaultdict(set)
        # ledger: accumulate commit signatures per (target, n) until quorum, then seal block
        self._commit_sigs = defaultdict(dict)   # (target, n) -> {node_id: sig bytes}
        self._ledger_pending = {}               # (target, n) -> records list (waiting for sigs)
        self.behavior, self.mute = 'honest', False
        self.sent = self.ok = self.bad = self.forwarded = self.fwd_window = 0
        self.events, self.tasks, self.alive = [], [], False
        # ledger – created in start() so pub_keys are ready
        self.chain: Chain = None
    now = staticmethod(time.monotonic)
    def event(self, msg): self.events.append((self.now(), msg))

    async def start(self):
        self.loop = asyncio.get_running_loop(); self.txq = asyncio.Queue()
        self.transport, _ = await self.loop.create_datagram_endpoint(lambda: self, local_addr=('127.0.0.1', self.cfg.base_port + self.id))
        self.hub = ('127.0.0.1', self.cfg.base_port - 1); self.alive = True
        # Initialise ledger (itadori mode only)
        if self.itadori:
            self.chain = Chain(self.id, self.cfg.cluster, self.prov.pub,
                               knet=self.prov.knet,
                               data_dir=self.cfg.ledger_dir)
        self.tasks = [self.loop.create_task(c) for c in (self.tx_loop(), self.hello_loop(), self.lsa_loop(), self.data_loop(), self.gc_loop())]
    def stop(self):
        self.alive = False
        for t in self.tasks: t.cancel()
        self.transport.close()

    # ---- radio ----
    def send(self, f, delay=0.0):
        data = P.build(f, self.prov.knet)
        if delay: self.loop.call_later(delay * self.scale, self.txq.put_nowait, data)
        else: self.txq.put_nowait(data)
    async def tx_loop(self):
        while True:
            data = await self.txq.get()
            self.transport.sendto(bytes([self.id]) + data, self.hub)
            await asyncio.sleep(airtime(len(data)) * self.scale)  # half duplex: one frame on air at a time
    def datagram_received(self, data, addr):
        f = P.parse(data, self.prov.knet) if self.alive else None
        if f is None or f.sender == self.id or (self.itadori and f.sender in self.quarantined): return
        if f.type == P.HELLO: self.on_hello(f)
        elif f.type == P.LSA: self.on_lsa(f)
        elif f.type == P.DATA: self.on_data(f)
        elif f.type == P.CTRL and self.itadori: self.on_ctrl(f)

    # ---- neighbours and link state ----
    async def hello_loop(self):
        await asyncio.sleep(self.rng.random() * self.cfg.hello * self.scale)
        while True:
            # Piggyback 10-byte ledger head summary on HELLO if itadori mode
            extra = self.chain.head_summary() if (self.itadori and self.chain) else b''
            self.send(P.Frame(P.HELLO, self.id, self.id, P.BCAST, self.hello_seq, 1, extra)); self.hello_seq += 1
            await asyncio.sleep(self.cfg.hello * self.scale)
            dead = [n for n, h in self.hist.items() if self.now() - h['t'] > 4 * self.cfg.hello * self.scale]
            for n in dead: del self.hist[n]
            if dead: self.send_lsa()  # triggered update: react to a lost neighbour immediately
    def on_hello(self, f):
        h = self.hist.setdefault(f.sender, {'seqs': set(), 'max': -1, 't': 0})
        h['seqs'].add(f.seq); h['max'] = max(h['max'], f.seq); h['t'] = self.now()
        if len(h['seqs']) > 40: h['seqs'] = {s for s in h['seqs'] if s > h['max'] - 16}
        # Ledger sync: if peer advertises a taller/different chain, request missing blocks
        if self.itadori and self.chain and len(f.payload) >= 10:
            peer_hash = f.payload[:8]
            peer_height = struct.unpack('>H', f.payload[8:10])[0]
            my_head = self.chain.head()
            if peer_height > my_head.height or (peer_height == my_head.height and peer_hash != my_head.block_hash[:8]):
                # Request blocks from (my_height+1) onward
                self._request_blocks(f.sender, my_head.height + 1)
    def link_q(self, n):
        h = self.hist[n]
        return max(0.05, sum(1 for s in h['seqs'] if s > h['max'] - 16) / min(16, h['max'] + 1))
    async def lsa_loop(self):
        await asyncio.sleep((self.cfg.hello * 1.5 + self.rng.random() * self.cfg.lsa * 0.5) * self.scale)
        while True:
            self.send_lsa(); await asyncio.sleep(self.cfg.lsa * self.scale)
    def send_lsa(self):
        nb = {n: int(self.link_q(n) * 255) for n in self.hist}
        load = min(255, self.fwd_window); self.fwd_window = 0; self.lsa_seq += 1
        self.lsdb[self.id] = {'seq': self.lsa_seq, 'nbrs': {n: q / 255 for n, q in nb.items()}, 'load': load, 't': self.now()}
        self.send(P.Frame(P.LSA, self.id, self.id, P.BCAST, self.lsa_seq, 6, bytes([load]) + b''.join(bytes([n, q]) for n, q in nb.items())))
    def on_lsa(self, f):
        cur = self.lsdb.get(f.origin)
        if f.origin == self.id or (cur and f.seq <= cur['seq']): return
        pl = f.payload
        self.lsdb[f.origin] = {'seq': f.seq, 'nbrs': {pl[i]: pl[i + 1] / 255 for i in range(1, len(pl) - 1, 2)}, 'load': pl[0], 't': self.now()}
        if f.ttl > 1: self.send(f.copy(sender=self.id, ttl=f.ttl - 1), delay=self.rng.random() * 0.3)
    def next_hop(self):
        bad = self.quarantined if self.itadori else set(); now = self.now(); edges = []
        for v, e in self.lsdb.items():
            if v in bad or (v != self.id and now - e['t'] > 8 * self.cfg.lsa * self.scale): continue
            for u, q in e['nbrs'].items():
                eu = self.lsdb.get(u)
                if u in bad or not eu or v not in eu['nbrs']: continue  # a link counts only if both ends report it
                edges.append((u, v, 1.0 if not self.itadori else 1 / max(q, 0.05) + 0.04 * e['load']))
        dist, nxt = {self.cfg.gw: 0.0}, {}
        for _ in range(len(self.lsdb) + 1):  # Bellman-Ford towards the gateway
            changed = False
            for u, v, c in edges:
                if v in dist and dist[v] + c < dist.get(u, 1e9) - 1e-9: dist[u], nxt[u], changed = dist[v] + c, v, True
            if not changed: break
        return nxt.get(self.id)

    # ---- data plane and watchdog ----
    async def data_loop(self):
        if self.id == self.cfg.gw: return
        await asyncio.sleep((self.cfg.warm + self.rng.random() * self.cfg.data) * self.scale)
        while True:
            self.dseq = (self.dseq + 1) & 0xFFFF; self.sent += 1
            nh = self.next_hop()
            if nh is not None:
                app = struct.pack('>I', self.dseq) + b'itadori'
                self.tx_data(P.Frame(P.DATA, self.id, self.id, nh, self.dseq, 12, P.e2e_tag(self.prov.e2e[self.id], self.id, self.dseq, app) + app))
            await asyncio.sleep(self.cfg.data * self.scale * (0.8 + 0.4 * self.rng.random()))
    def tx_data(self, f):
        self.send(f); self.send(f, delay=0.4)  # two copies per hop; receivers deduplicate
        if self.itadori and f.nexthop != self.cfg.gw:  # watchdog: listen for the next hop to forward it unchanged
            self.pending[(f.origin, f.seq)] = (f.nexthop, hashlib.sha1(f.payload).digest()[:6], self.now() + 10 * self.scale)
    def on_data(self, f):
        key = (f.origin, f.seq); p = self.pending.get(key)
        if self.itadori:  # overhearing watchdog: anyone who hears a packet go in and come out changed can accuse the relay
            h = hashlib.sha1(f.payload).digest()[:6]; prev = self.heard.get(key)
            if prev and f.sender == prev[1] and f.sender != prev[0] and prev[2] != h: self.accuse(f.sender)
            if not prev or f.sender == prev[1]: self.heard[key] = (f.sender, f.nexthop, h, self.now() + 15 * self.scale)
        if p and f.sender == p[0]:
            del self.pending[key]
            if hashlib.sha1(f.payload).digest()[:6] != p[1]: self.accuse(f.sender)
            return
        if f.nexthop != self.id or key in self.seen: return
        self.seen.add(key)
        if self.id == self.cfg.gw:
            tag, app = f.payload[:8], f.payload[8:]
            if hmac.compare_digest(tag, P.e2e_tag(self.prov.e2e[f.origin], f.origin, f.seq, app)): self.ok += 1
            else: self.bad += 1
            return
        nh = self.next_hop()
        if f.ttl <= 1 or nh is None: return
        pl = f.payload[:-1] + bytes([f.payload[-1] ^ 1]) if self.behavior == 'tamper' else f.payload
        self.forwarded += 1; self.fwd_window += 1
        self.tx_data(f.copy(sender=self.id, nexthop=nh, ttl=f.ttl - 1, payload=pl))
    async def gc_loop(self):
        while True:
            await asyncio.sleep(20 * self.scale)
            self.pending = {k: v for k, v in self.pending.items() if v[2] > self.now()}
            self.heard = {k: v for k, v in self.heard.items() if v[3] > self.now()}
            if len(self.seen) > 4000: self.seen.clear()

    # ---- trust: signed accusations and PBFT-style quarantine consensus ----
    def accuse(self, k):
        if self.now() - self.last_accuse.get(k, -1e9) < 10 * self.scale: return
        self.last_accuse[k] = self.now(); self.send_ctrl(P.ACCUSE, bytes([k]))
    def send_ctrl(self, ctype, body):
        self.cseq += 1
        sig = P.sign(self.prov.priv[self.id], ctype, body, self.id, self.cseq)
        f = P.Frame(P.CTRL, self.id, self.id, P.BCAST, self.cseq, 6, bytes([ctype]) + body + sig)
        self.cseen.add((self.id, self.cseq, ctype)); self.send(f); self.send(f, delay=0.4)
        self.process_ctrl(self.id, ctype, body, raw_sig=(self.cseq, sig))
    def on_ctrl(self, f):
        ctype, body, sig = f.payload[0], f.payload[1:-P.SIG], f.payload[-P.SIG:]; key = (f.origin, f.seq, ctype)
        pub = self.prov.pub.get(f.origin)
        if key in self.cseen or not pub or not P.verify(pub, sig, ctype, body, f.origin, f.seq): return
        self.cseen.add(key)
        # BLOCK_REQ and BLOCK_RESP are point-to-point (not flooded)
        if ctype in (P.BLOCK_REQ, P.BLOCK_RESP):
            self.process_ctrl(f.origin, ctype, body, raw_sig=(f.seq, sig)); return
        if f.ttl > 1: self.send(f.copy(sender=self.id, ttl=f.ttl - 1), delay=self.rng.random() * 0.3)
        self.process_ctrl(f.origin, ctype, body, raw_sig=(f.seq, sig))
    def process_ctrl(self, origin, ctype, body, raw_sig=None):
        cl = self.cfg.cluster; quorum = 2 * ((len(cl) - 1) // 3) + 1; k = body[0]
        n = struct.unpack('>H', body[1:3])[0] if len(body) >= 3 else 0
        if ctype == P.ACCUSE: self.accusers[k].add(origin); self.maybe_propose(k)
        elif ctype == P.PREPREPARE and origin == cl[0]: self.pp.add((k, n))
        elif ctype == P.PREPARE and origin in cl: self.prepares[(k, n)].add(origin)
        elif ctype == P.COMMIT and origin in cl:
            self.commits[(k, n)].add(origin)
            # Collect commit signatures for the ledger
            if self.itadori and self.chain and raw_sig is not None:
                self._commit_sigs[(k, n)][origin] = raw_sig
            if len(self.commits[(k, n)]) >= quorum and k not in self.quarantined:
                self.quarantined.add(k); self.event(f'node {k} quarantined')
                # Seal ledger block once quorum commits reached
                if self.itadori and self.chain:
                    self._seal_ledger_block(k, n, quorum)
        elif ctype == P.BLOCK_REQ and self.chain:
            # Peer requests blocks from 'from_height' (body[1:3])
            from_height = struct.unpack('>H', body[1:3])[0] if len(body) >= 3 else 1
            self._send_blocks(origin, from_height)
        elif ctype == P.BLOCK_RESP and self.chain:
            # Incoming block from peer
            try:
                from .ledger import Block
                blk = Block.from_wire(body[1:])  # body[0] is the ctype echo
                self.chain.accept(blk)
                self.event(f'ledger synced block {blk.height}')
            except Exception:
                pass  # bad/stale block – ignore
        self.advance(quorum)

    def _seal_ledger_block(self, target: int, cseq_n: int, quorum: int):
        """Create and append a ledger block for a just-reached quarantine quorum."""
        accusers = sorted(self.accusers[target] - {target})
        records = [quarantine_record(target, accusers, cseq_n)]
        sigs = dict(self._commit_sigs.get((target, cseq_n), {}))
        # Ensure our own signature is present if we are in the cluster
        if self.id in self.cfg.cluster and self.id not in sigs:
            body = bytes([target]) + struct.pack('>H', cseq_n)
            self.cseq += 1
            my_sig = P.sign(self.prov.priv[self.id], P.COMMIT, body, self.id, self.cseq)
            sigs[self.id] = (self.cseq, my_sig)
        try:
            self.chain.append(records, sigs)
            self.event(f'ledger block {self.chain.height} sealed (quarantine node {target})')
        except Exception as e:
            self.event(f'ledger seal failed: {e}')

    def _request_blocks(self, peer_id: int, from_height: int):
        """Send a BLOCK_REQ CTRL to peer_id asking for blocks from from_height."""
        body = bytes([P.BLOCK_REQ]) + struct.pack('>H', min(from_height, 0xFFFF))
        self.cseq += 1
        sig = P.sign(self.prov.priv[self.id], P.BLOCK_REQ, body[1:], self.id, self.cseq)
        peer_port = self.cfg.base_port + peer_id
        frame = P.Frame(P.CTRL, self.id, self.id, peer_id, self.cseq, 1, bytes([P.BLOCK_REQ]) + body[1:] + sig)
        raw = bytes([self.id]) + P.build(frame, self.prov.knet)
        self.loop.call_soon(self.transport.sendto, raw, self.hub)

    def _send_blocks(self, requester_id: int, from_height: int):
        """Send BLOCK_RESP frames to requester for each block from from_height."""
        if not self.chain: return
        for h in range(from_height, self.chain.height + 1):
            blk = self.chain.get_block(h)
            if blk is None: break
            wire = blk.to_wire()
            body = bytes([P.BLOCK_RESP]) + wire
            # Must fit in one frame; truncate sigs if necessary to stay <=255 bytes
            if len(body) + P.SIG + 8 > P.MAX_FRAME:  # 8 = header
                # Strip sigs down to quorum worth to fit
                from .ledger import Block as _Blk
                q = 2 * ((len(self.cfg.cluster) - 1) // 3) + 1
                trimmed = dict(list(blk.sigs.items())[:q])
                blk2 = _Blk(blk.height, blk.prev_hash, blk.records, blk.block_hash, trimmed)
                body = bytes([P.BLOCK_RESP]) + blk2.to_wire()
            self.cseq += 1
            sig = P.sign(self.prov.priv[self.id], P.BLOCK_RESP, body[1:], self.id, self.cseq)
            frame = P.Frame(P.CTRL, self.id, self.id, requester_id, self.cseq, 1, body + sig)
            raw_frame = P.build(frame, self.prov.knet)
            if len(raw_frame) <= P.MAX_FRAME:
                delay = (h - from_height) * 0.1 * self.scale
                self.send(frame, delay=delay)

    def evidence(self, k): return len(self.accusers[k] - {k}) >= 2  # at least two distinct signed accusers
    def maybe_propose(self, k):
        if self.id == self.cfg.cluster[0] and not self.mute and k not in self.proposed and k not in self.quarantined and self.evidence(k):
            self.proposed.add(k); self.n += 1; self.send_ctrl(P.PREPREPARE, bytes([k]) + struct.pack('>H', self.n))
    def advance(self, quorum):
        if self.id not in self.cfg.cluster or self.mute: return
        for k, n in list(self.pp):
            body = bytes([k]) + struct.pack('>H', n)
            if (k, n) not in self.voted and self.evidence(k): self.voted.add((k, n)); self.send_ctrl(P.PREPARE, body)
            if len(self.prepares[(k, n)]) >= quorum and (k, n) not in self.sent_commit: self.sent_commit.add((k, n)); self.send_ctrl(P.COMMIT, body)
