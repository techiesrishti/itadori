"""Test and demo harness: starts N independent nodes plus the radio emulator, injects faults, measures delivery at the gateway."""
import asyncio, random, time
from . import protocol as P
from .air import Air
from .node import Config, Node
from .resilience import analyze_topology
from .sos import pack_sos_payload, CODE_MAP

POSITIONS = [(0, 1), (1, 0), (1, 1), (1, 2), (2, 0), (2, 1), (2, 2), (3, 1)]  # node 0 is the gateway
RADIO_RANGE = 1.5

class Network:
    def __init__(self, mode='itadori', scale=0.04, seed=1, positions=POSITIONS, cluster=(0, 1, 3, 6), ledger_dir=None):
        self.cfg = Config(mode=mode, scale=scale, seed=seed, cluster=cluster, base_port=random.randint(20000, 60000), ledger_dir=ledger_dir)
        self.positions, self.prov = positions, P.Provision(len(positions), seed)
    async def start(self):
        self.air = Air(self.positions, RADIO_RANGE, self.cfg.scale, self.cfg.base_port, self.cfg.seed); await self.air.start()
        self.nodes = [Node(i, self.cfg, self.prov) for i in range(len(self.positions))]
        await asyncio.gather(*(n.start() for n in self.nodes))
    async def stop(self):
        for n in self.nodes:
            if n.alive: n.stop()
        self.air.stop(); await asyncio.sleep(0.05)
    async def sleep(self, protocol_seconds): await asyncio.sleep(protocol_seconds * self.cfg.scale)
    # faults
    def crash(self, i): self.nodes[i].stop(); self.air.dead.add(i)
    def cut(self, a, b): self.air.cut.add((min(a, b), max(a, b)))
    def degrade(self, i, q=0.4): self.air.txq[i] = q
    def malicious(self, i): self.nodes[i].behavior = 'tamper'
    def mute(self, i): self.nodes[i].mute = True
    def busiest(self): return max((n for n in self.nodes if n.id != self.cfg.gw), key=lambda n: n.forwarded).id
    # measurement
    def snapshot(self):
        return (sum(n.sent for n in self.nodes if n.id != self.cfg.gw), self.nodes[self.cfg.gw].ok, self.nodes[self.cfg.gw].bad)
    async def measure(self, protocol_seconds):
        s0 = self.snapshot(); await self.sleep(protocol_seconds); s1 = self.snapshot()
        sent, ok, bad = (b - a for a, b in zip(s0, s1)); sent = max(sent, 1)
        return {'sent': sent, 'delivery': min(1.0, ok / sent), 'corrupted': min(1.0, bad / sent)}
    # ledger helpers
    def ledger_state(self):
        """Return ledger info for all itadori-mode nodes: height, head hash, agreement."""
        chains = {n.id: n.chain for n in self.nodes if n.chain is not None}
        if not chains:
            return {'height': 0, 'head': '—', 'agree': True, 'intact': True}
        heights = {nid: c.height for nid, c in chains.items()}
        heads = {nid: c.head().block_hash[:8].hex() for nid, c in chains.items()}
        max_h = max(heights.values())
        head_at_max = [h for nid, h in heads.items() if heights[nid] == max_h]
        agree = len(set(head_at_max)) == 1
        intact = all(c.is_intact() for c in chains.values())
        sample_chain = next(iter(chains.values()))
        return {'height': max_h, 'head': sample_chain.head().block_hash[:8].hex(),
                'agree': agree, 'intact': intact, 'per_node': heights}

    # features: SOS, Resilience, Scenarios, Incident Reporting
    def send_sos(self, origin_id, code_str='TRAPPED', victims=1, lat_offset=0.0, lon_offset=0.0):
        """Trigger an emergency SOS alert from a survivor node."""
        if origin_id < 0 or origin_id >= len(self.nodes):
            return False
        node = self.nodes[origin_id]
        if not node.alive:
            return False
        code = CODE_MAP.get(code_str.upper(), 1)
        return node.trigger_sos(code=code, victims=victims, lat_offset=lat_offset, lon_offset=lon_offset)

    def get_resilience(self):
        """Live graph-theoretic resilience & SPOF analysis of current mesh."""
        alive_nodes = set(n.id for n in self.nodes if n.alive)
        active_links = []
        for (a, b) in self.air.q:
            if a < b and a in alive_nodes and b in alive_nodes:
                edge = (min(a, b), max(a, b))
                if edge not in self.air.cut:
                    active_links.append(edge)
        return analyze_topology(alive_nodes, active_links, gw=self.cfg.gw)

    def run_scenario(self, name):
        """Execute a scripted disaster scenario."""
        name = name.lower()
        if name in ('flood', 'flash_flood'):
            # Flash flood: cuts perimeter links and drowns outer nodes
            self.cut(1, 4)
            self.cut(3, 7)
            if len(self.nodes) > 4:
                self.degrade(4, q=0.2)
            if len(self.nodes) > 7:
                self.nodes[7].trigger_sos(code=CODE_MAP['FLOOD'], victims=3, lat_offset=0.01, lon_offset=-0.01)
            return {'scenario': 'Flash Flood', 'status': 'Perimeter severed, Node 7 issued FLOOD SOS'}
        elif name in ('byzantine', 'infiltration'):
            # Byzantine attack: turns busiest relay malicious
            target = self.busiest()
            self.malicious(target)
            return {'scenario': 'Byzantine Infiltration', 'status': f'Node {target} turned malicious (tampering packets)'}
        elif name in ('cascade', 'relay_cascade'):
            # Cascade: primary relay crashes, secondary is degraded
            b1 = self.busiest()
            self.crash(b1)
            b2 = self.busiest()
            self.degrade(b2, q=0.3)
            return {'scenario': 'Relay Cascade', 'status': f'Primary relay Node {b1} crashed, Node {b2} degraded'}
        return {'scenario': name, 'status': 'Unknown scenario'}

    def export_incident_report(self):
        """Generate a structured disaster forensics & incident response report."""
        gw = self.nodes[self.cfg.gw]
        resilience = self.get_resilience()
        ledger = self.ledger_state()
        quarantines = list(getattr(gw, 'quarantined', set()))
        sos_events = getattr(gw, 'sos_log', [])
        return {
            'timestamp': time.time(),
            'network_mode': self.cfg.mode,
            'nodes_total': len(self.nodes),
            'nodes_alive': sum(1 for n in self.nodes if n.alive),
            'delivery_stats': {
                'ok': gw.ok,
                'bad': gw.bad,
                'total_sent': sum(n.sent for n in self.nodes if n.id != self.cfg.gw)
            },
            'resilience': resilience,
            'ledger': ledger,
            'quarantined_nodes': quarantines,
            'sos_alerts': sos_events,
            'cuts': list(self.air.cut),
            'dead_nodes': list(self.air.dead)
        }
