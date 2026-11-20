"""
Tests for the Itadori permissioned ledger (itadori/ledger.py).

Run with:  python -m unittest -v tests.test_ledger
All timings use a fast scale (0.04) so the suite finishes in roughly 1-2 minutes.
"""
import asyncio, hashlib, os, struct, tempfile, unittest

from itadori import protocol as P
from itadori.ledger import (
    Chain, Block, block_hash, quarantine_record, _genesis_prev_hash
)
from itadori.network import Network


# ---------------------------------------------------------------------------
# Helper: build a minimal Chain with a provisional key set
# ---------------------------------------------------------------------------
def _make_chain(node_id=0, data_dir=None, prov=None, knet=None):
    if prov is None:
        prov = P.Provision(4, seed=42)
    if knet is None:
        knet = prov.knet
    cluster = (0, 1, 2, 3)
    chain = Chain(node_id, cluster, prov.pub, knet=knet, data_dir=data_dir)
    return chain, prov


def _quorum_sigs(prov, chain_obj, records):
    """Sign the next block_hash with a quorum (3 of 4) of cluster keys."""
    prev = chain_obj.head()
    bh = block_hash(prev.height + 1, prev.block_hash, records)
    sigs = {}
    for nid in (0, 1, 2):          # 3 of 4 = quorum
        sigs[nid] = prov.priv[nid].sign(bh)
    return sigs


# ---------------------------------------------------------------------------
# 1. Chain append and verify; tampering detected
# ---------------------------------------------------------------------------
class TestChainIntegrity(unittest.TestCase):

    def _seal(self, chain, prov, target=5):
        records = [quarantine_record(target, [1, 2], cseq=1)]
        sigs = _quorum_sigs(prov, chain, records)
        return chain.append(records, sigs)

    def test_genesis_deterministic_same_provision(self):
        """Two Chain instances from the SAME Provision must have identical genesis."""
        prov = P.Provision(4, seed=42)
        c1 = Chain(0, (0,1,2,3), prov.pub, knet=prov.knet)
        c2 = Chain(1, (0,1,2,3), prov.pub, knet=prov.knet)
        self.assertEqual(c1.head().block_hash, c2.head().block_hash)

    def test_different_knet_gives_different_genesis(self):
        """Different network keys must produce different genesis blocks."""
        p1 = P.Provision(4, seed=1)
        p2 = P.Provision(4, seed=2)
        c1 = Chain(0, (0,1,2,3), p1.pub, knet=p1.knet)
        c2 = Chain(0, (0,1,2,3), p2.pub, knet=p2.knet)
        self.assertNotEqual(c1.head().block_hash, c2.head().block_hash)

    def test_append_and_verify(self):
        c, prov = _make_chain()
        blk = self._seal(c, prov)
        self.assertEqual(blk.height, 1)
        self.assertEqual(blk.prev_hash, c.get_block(0).block_hash)
        c.verify_chain()          # must not raise

    def test_tamper_record_detected(self):
        c, prov = _make_chain()
        self._seal(c, prov)
        c.tamper(1)               # flip target byte
        self.assertFalse(c.is_intact())
        with self.assertRaises(ValueError):
            c.verify_chain()

    def test_tamper_prev_hash_detected(self):
        c, prov = _make_chain()
        self._seal(c, prov)
        # Directly corrupt the prev_hash field
        blk = c._blocks[1]
        c._blocks[1] = Block(
            height=blk.height,
            prev_hash=bytes(32),   # all-zeros: wrong
            records=blk.records,
            block_hash=blk.block_hash,
            sigs=blk.sigs,
        )
        with self.assertRaises(ValueError):
            c.verify_chain()

    def test_wrong_block_hash_detected(self):
        c, prov = _make_chain()
        self._seal(c, prov)
        blk = c._blocks[1]
        c._blocks[1] = Block(
            height=blk.height,
            prev_hash=blk.prev_hash,
            records=blk.records,
            block_hash=bytes(32),   # wrong hash
            sigs=blk.sigs,
        )
        with self.assertRaises(ValueError):
            c.verify_chain()

    def test_forged_block_rejected(self):
        """A block with wrong signatures (not from cluster keys) must be rejected."""
        prov_bad = P.Provision(4, seed=99)   # different keys
        c, prov = _make_chain()
        records = [quarantine_record(5, [1, 2], cseq=1)]
        prev = c.head()
        bh = block_hash(1, prev.block_hash, records)
        # Sign with WRONG keys
        bad_sigs = {nid: prov_bad.priv[nid].sign(bh) for nid in (0, 1, 2)}
        blk = Block(height=1, prev_hash=prev.block_hash,
                    records=records, block_hash=bh, sigs=bad_sigs)
        with self.assertRaises(ValueError):
            c.accept(blk)

    def test_bad_prev_hash_rejected(self):
        c, prov = _make_chain()
        records = [quarantine_record(5, [1, 2], cseq=1)]
        # Compute block_hash with WRONG prev_hash so the link is broken
        wrong_prev = bytes(32)
        bh = block_hash(1, wrong_prev, records)
        sigs = {nid: prov.priv[nid].sign(bh) for nid in (0, 1, 2)}
        blk = Block(height=1, prev_hash=wrong_prev,
                    records=records, block_hash=bh, sigs=sigs)
        with self.assertRaises(ValueError):
            c.accept(blk)

    def test_persistence_roundtrip(self):
        prov = P.Provision(4, seed=42)
        with tempfile.TemporaryDirectory() as d:
            c, _ = _make_chain(data_dir=d, prov=prov)
            self._seal(c, prov, target=3)
            # Reload with the same prov (same knet)
            c2 = Chain(0, (0,1,2,3), prov.pub, knet=prov.knet, data_dir=d)
            self.assertEqual(c2.height, 1)
            c2.verify_chain()

    def test_broken_chain_on_load_raises(self):
        prov = P.Provision(4, seed=42)
        with tempfile.TemporaryDirectory() as d:
            c, _ = _make_chain(data_dir=d, prov=prov)
            self._seal(c, prov, target=3)
            # Corrupt the file on disk
            path = os.path.join(d, 'node_0.jsonl')
            with open(path) as f:
                data = f.read()
            with open(path, 'w') as f:
                f.write(data.replace('"target": 3', '"target": 99'))
            with self.assertRaises(ValueError):
                Chain(0, (0,1,2,3), prov.pub, knet=prov.knet, data_dir=d)


# ---------------------------------------------------------------------------
# 2. Wire size: no ledger frame exceeds 255 bytes
# ---------------------------------------------------------------------------
class TestFrameSize(unittest.TestCase):

    def test_block_resp_fits_in_lora_frame(self):
        """BLOCK_RESP wire format (1 sig only) + CTRL overhead must fit in 255 bytes."""
        c, prov = _make_chain()
        records = [quarantine_record(5, [1, 2], cseq=1)]
        sigs = _quorum_sigs(prov, c, records)
        blk = c.append(records, sigs)
        wire = blk.to_wire()   # compact: 1 sig only
        # Simulate the full CTRL BLOCK_RESP frame:
        # payload = ctype_byte(1) + wire + Ed25519_sig(64)
        # frame  = HDR(8) + payload + MAC(8)
        total = 1 + len(wire) + P.SIG + 8 + P.MAC
        self.assertLessEqual(total, P.MAX_FRAME,
            f'BLOCK_RESP frame too large: {total} bytes')

    def test_hello_with_ledger_piggyback_fits(self):
        c, prov = _make_chain()
        summary = c.head_summary()   # 10 bytes
        # Build a HELLO frame with 10-byte payload
        f = P.Frame(P.HELLO, 0, 0, P.BCAST, 1, 1, summary)
        raw = P.build(f, prov.knet)
        self.assertLessEqual(len(raw), P.MAX_FRAME)
        self.assertEqual(len(summary), 10)

    def test_wire_roundtrip(self):
        c, prov = _make_chain()
        records = [quarantine_record(5, [1, 2], cseq=1)]
        sigs = _quorum_sigs(prov, c, records)
        blk = c.append(records, sigs)
        blk2 = Block.from_wire(blk.to_wire())
        self.assertEqual(blk2.height, blk.height)
        self.assertEqual(blk2.block_hash, blk.block_hash)
        self.assertEqual(blk2.records, blk.records)
        self.assertEqual(len(blk2.sigs), 1)   # wire carries only 1 sig


# ---------------------------------------------------------------------------
# 3. Integration: malicious relay quarantined → all honest nodes hold identical chains
# ---------------------------------------------------------------------------
class TestLedgerIntegration(unittest.IsolatedAsyncioTestCase):

    async def test_quarantine_produces_matching_chains(self):
        net = Network('itadori', scale=0.04)
        await net.start()
        await net.sleep(60)
        bad = net.busiest()
        net.malicious(bad)
        # Wait until quarantine is triggered, then allow consensus to settle
        for _ in range(15):
            await net.sleep(10)
            if any(bad in n.quarantined for n in net.nodes):
                break
        await net.sleep(30)

        chains = [n.chain for n in net.nodes if n.chain is not None and n.alive]
        self.assertGreater(len(chains), 0)

        # At least the nodes that quarantined should have height >= 1
        sealed = [c for c in chains if c.height >= 1]
        self.assertGreater(len(sealed), 0, 'No node sealed a ledger block')

        # All sealed chains at the same height must agree on the head hash
        by_height = {}
        for c in sealed:
            by_height.setdefault(c.height, set()).add(c.head().block_hash)
        for h, hashes in by_height.items():
            self.assertEqual(len(hashes), 1, f'Chain fork at height {h}')

        # Every sealed chain must pass verification
        for c in sealed:
            c.verify_chain()

        await net.stop()

    async def test_quarantine_with_one_silent_cluster_member(self):
        """Consensus and ledger sealing must still work with one silent cluster member."""
        net = Network('itadori', scale=0.04)
        await net.start()
        await net.sleep(60)
        bad = net.busiest()
        mute = next(i for i in (3, 6, 1) if i != bad)
        net.mute(mute)
        net.malicious(bad)
        for _ in range(15):
            await net.sleep(10)
            if any(bad in n.quarantined for n in net.nodes if n.id != mute):
                break
        await net.sleep(30)

        chains = [n.chain for n in net.nodes
                  if n.chain is not None and n.alive and n.id != mute]
        sealed = [c for c in chains if c.height >= 1]
        self.assertGreater(len(sealed), 0)
        for c in sealed:
            c.verify_chain()

        await net.stop()

    async def test_crashed_node_syncs_on_restart(self):
        """
        A node crashed during the quarantine decision catches up after restart.
        We simulate the catch-up path by directly calling chain.accept() with
        a block from a peer that has it.
        """
        net = Network('itadori', scale=0.04)
        await net.start()
        await net.sleep(60)
        bad = net.busiest()

        # Crash a node before the malicious fault
        crash_id = 5 if bad != 5 else 4
        net.crash(crash_id)

        net.malicious(bad)
        for _ in range(15):
            await net.sleep(10)
            if any(bad in n.quarantined for n in net.nodes if n.id != crash_id):
                break
        await net.sleep(30)

        # Find a node that sealed the block
        donor = next((n for n in net.nodes if n.chain and n.chain.height >= 1), None)
        self.assertIsNotNone(donor, 'No block sealed')

        # Simulate the crashed node restarting with an empty in-memory chain
        fresh_chain = Chain(crash_id, net.cfg.cluster, net.prov.pub,
                            knet=net.prov.knet)
        # Accept the block from the donor (1-sig wire format)
        blk_wire = donor.chain.get_block(1)
        wire_bytes = blk_wire.to_wire()
        blk_recv = Block.from_wire(wire_bytes)
        fresh_chain.accept(blk_recv)   # must not raise
        self.assertEqual(fresh_chain.height, 1)
        self.assertEqual(fresh_chain.head().block_hash, donor.chain.get_block(1).block_hash)

        await net.stop()


if __name__ == '__main__':
    unittest.main()
