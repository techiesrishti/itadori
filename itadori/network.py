"""Test and demo harness: starts N independent nodes plus the radio emulator, injects faults, measures delivery at the gateway."""
import asyncio, random
from . import protocol as P
from .air import Air
from .node import Config, Node

POSITIONS = [(0, 1), (1, 0), (1, 1), (1, 2), (2, 0), (2, 1), (2, 2), (3, 1)]  # node 0 is the gateway
RADIO_RANGE = 1.5

class Network:
    def __init__(self, mode='itadori', scale=0.04, seed=1, positions=POSITIONS, cluster=(0, 1, 3, 6)):
        self.cfg = Config(mode=mode, scale=scale, seed=seed, cluster=cluster, base_port=random.randint(20000, 60000))
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
