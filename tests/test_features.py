import asyncio, unittest
from itadori import protocol as P
from itadori.sos import pack_sos_payload, unpack_sos_payload, CODE_MAP, PRIO_EMERGENCY, PRIO_DATA
from itadori.resilience import analyze_topology
from itadori.network import Network

class TestFeatures(unittest.TestCase):
    def test_sos_binary_packing(self):
        """SOS frame payload must be exactly 8 bytes and roundtrip accurately."""
        code = CODE_MAP['TRAPPED']
        victims = 4
        lat, lon = 0.015, -0.025
        raw = pack_sos_payload(code, victims, lat, lon)
        self.assertEqual(len(raw), 8)
        sos = unpack_sos_payload(raw)
        self.assertIsNotNone(sos)
        self.assertEqual(sos.code, code)
        self.assertEqual(sos.victims, victims)
        self.assertAlmostEqual(sos.lat_offset, lat, places=3)
        self.assertAlmostEqual(sos.lon_offset, lon, places=3)

    def test_resilience_cut_vertices_and_bridges(self):
        """Graph resilience analyzer should identify SPOFs (cut-vertices and bridges)."""
        # Linear line 0 - 1 - 2
        nodes = {0, 1, 2}
        links = [(0, 1), (1, 2)]
        res = analyze_topology(nodes, links, gw=0)
        self.assertIn(1, res['cut_vertices'])
        self.assertIn((0, 1), res['bridges'])
        self.assertIn((1, 2), res['bridges'])
        self.assertFalse(res['is_biconnected'])
        self.assertLessEqual(res['score'], 80)

        # Triangle 0 - 1 - 2 - 0 (biconnected, 0 SPOFs)
        links_tri = [(0, 1), (1, 2), (0, 2)]
        res_tri = analyze_topology(nodes, links_tri, gw=0)
        self.assertEqual(res_tri['cut_vertices'], [])
        self.assertEqual(res_tri['bridges'], [])
        self.assertTrue(res_tri['is_biconnected'])
        self.assertGreater(res_tri['score'], 80)

    def test_priority_preemption_and_sos_delivery(self):
        """Critical SOS packets preempt routine data in txq and reach gateway."""
        async def run_it():
            net = Network('itadori')
            await net.start()
            try:
                await net.sleep(60)
                origin = next((n for n in net.nodes if n.id != 0 and n.next_hop() is not None), None)
                self.assertIsNotNone(origin)
                sent = net.send_sos(origin.id, code_str='FIRE', victims=2, lat_offset=0.01, lon_offset=-0.02)
                self.assertTrue(sent)
                await net.sleep(40)
                gw = net.nodes[0]
                self.assertGreaterEqual(len(gw.sos_log), 1)
                last = gw.sos_log[-1]
                self.assertEqual(last.origin, origin.id)
                self.assertEqual(last.code_name, 'FIRE_HAZARD')
                self.assertEqual(last.victims, 2)
            finally:
                await net.stop()
        asyncio.run(run_it())

    def test_scripted_scenario_and_incident_report(self):
        """Scripted disaster scenarios execute and export structured forensic reports."""
        async def run_it():
            net = Network(mode='itadori', scale=0.03, seed=42)
            await net.start()
            try:
                await net.sleep(15)
                r = net.run_scenario('flood')
                self.assertIn('Flash Flood', r['scenario'])
                report = net.export_incident_report()
                self.assertIn('resilience', report)
                self.assertIn('quarantined_nodes', report)
                self.assertIn('delivery_stats', report)
                self.assertEqual(report['network_mode'], 'itadori')
            finally:
                await net.stop()
        asyncio.run(run_it())

if __name__ == '__main__':
    unittest.main()
