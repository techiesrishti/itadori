import asyncio, unittest
from itadori import protocol as P
from itadori.lora import airtime
from itadori.network import Network

async def warmed(mode):
    net = Network(mode); await net.start(); await net.sleep(60); return net

class Wire(unittest.TestCase):
    def test_airtime_matches_deck_estimate(self): self.assertAlmostEqual(airtime(32), 0.0717, places=3)
    def test_tampered_frame_is_rejected(self):
        f = P.Frame(P.DATA, 1, 1, 0, 5, 8, b'hello'); buf = bytearray(P.build(f, b'k' * 16))
        self.assertIsNotNone(P.parse(bytes(buf), b'k' * 16)); buf[9] ^= 1
        self.assertIsNone(P.parse(bytes(buf), b'k' * 16))
    def test_forged_signature_is_rejected(self):
        prov = P.Provision(4); sig = P.sign(prov.priv[1], P.ACCUSE, b'\x02', 1, 7)
        self.assertTrue(P.verify(prov.pub[1], sig, P.ACCUSE, b'\x02', 1, 7))
        self.assertFalse(P.verify(prov.pub[2], sig, P.ACCUSE, b'\x02', 1, 7))  # another node cannot claim it
        self.assertFalse(P.verify(prov.pub[1], sig, P.ACCUSE, b'\x03', 1, 7))   # nor change what it said

class Mesh(unittest.IsolatedAsyncioTestCase):
    async def test_healthy_network_delivers(self):
        net = await warmed('itadori'); m = await net.measure(40); await net.stop()
        self.assertGreater(m['delivery'], 0.8); self.assertEqual(m['corrupted'], 0)
    async def test_recovers_from_relay_crash(self):
        net = await warmed('itadori'); relay = net.busiest(); net.crash(relay)
        await net.sleep(40); m = await net.measure(50); await net.stop()
        self.assertGreater(m['delivery'], 0.75)
    async def test_malicious_relay_is_quarantined(self):
        net = await warmed('itadori'); bad = net.busiest(); net.malicious(bad)
        await net.sleep(80); m = await net.measure(50); seen = {n.id for n in net.nodes if bad in n.quarantined}; await net.stop()
        self.assertGreaterEqual(len(seen), 6); self.assertLess(m['corrupted'], 0.05); self.assertGreater(m['delivery'], 0.7)
    async def test_plain_mesh_keeps_delivering_corrupted_data(self):
        net = await warmed('plain'); net.malicious(net.busiest()); await net.sleep(30); m = await net.measure(50); await net.stop()
        self.assertGreater(m['corrupted'], 0.1)
    async def test_quarantine_survives_one_silent_cluster_member(self):
        net = await warmed('itadori'); bad = net.busiest(); mute = next(i for i in (3, 6, 1) if i != bad); net.mute(mute); net.malicious(bad)
        await net.sleep(100); ok = sum(bad in n.quarantined for n in net.nodes if n.id != mute); await net.stop()
        self.assertGreaterEqual(ok, 5)

if __name__ == '__main__': unittest.main()

class Dash(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_serves_live_state_and_accepts_faults(self):
        import json, random
        from itadori.dashboard import Dashboard, serve
        d = Dashboard(0.04); await d.start(); port = random.randint(20000, 60000); srv = await serve(d, port)
        async def http(method, path):
            r, w = await asyncio.open_connection('127.0.0.1', port); w.write(f'{method} {path} HTTP/1.1\r\nHost: x\r\n\r\n'.encode()); await w.drain()
            data = await r.read(); w.close(); return data.split(b'\r\n\r\n', 1)[1]
        await asyncio.sleep(60 * 0.04)
        st = json.loads(await http('GET', '/state'))
        self.assertEqual(len(st['nets']), 2); self.assertEqual(len(st['nets'][1]['nodes']), 8)
        self.assertTrue(any(n['next'] is not None for n in st['nets'][1]['nodes']))
        self.assertIn(b'Itadori', await http('GET', '/'))
        msg = json.loads(await http('POST', '/fault?kind=malicious'))['msg']; self.assertIn('malicious', msg)
        await asyncio.sleep(80 * 0.04); st = json.loads(await http('GET', '/state'))
        self.assertTrue(any(n['quar'] for n in st['nets'][1]['nodes'])); self.assertFalse(any(n['quar'] for n in st['nets'][0]['nodes']))
        srv.close(); await d.stop()
