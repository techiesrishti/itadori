"""Radio emulator: the only simulated part. A UDP hub that delivers frames to in-range nodes with LoRa airtime, loss and range."""
import asyncio, collections, math, random, time
from .lora import airtime, link_quality

class Air(asyncio.DatagramProtocol):
    def __init__(self, positions, radio_range, scale, base_port, seed=1):
        self.pos, self.range, self.scale, self.base = positions, radio_range, scale, base_port
        self.rand = random.Random(seed); self.dead, self.cut, self.txq = set(), set(), {}
        self.frames = 0; self.airtime = 0.0; self.recent = collections.deque(maxlen=300)
        n = len(positions)
        self.q = {(a, b): link_quality(math.dist(positions[a], positions[b]), radio_range)
                  for a in range(n) for b in range(n) if a != b and math.dist(positions[a], positions[b]) <= radio_range}
    async def start(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(lambda: self, local_addr=('127.0.0.1', self.base - 1))
    def stop(self): self.transport.close()
    def error_received(self, exc): pass
    def deliver(self, frame, port):
        if not self.transport.is_closing(): self.transport.sendto(frame, ('127.0.0.1', port))
    def datagram_received(self, data, addr):
        sender, frame = data[0], data[1:]
        if sender in self.dead or len(frame) > 255: return
        self.frames += 1; t = airtime(len(frame)); self.airtime += t
        self.recent.append((time.monotonic(), sender, frame[0], frame[3]))  # for the dashboard: when, who, frame type, next hop
        for (a, b), q in self.q.items():
            if a != sender or b in self.dead or (min(a, b), max(a, b)) in self.cut: continue
            if self.rand.random() < q * self.txq.get(sender, 1.0):
                asyncio.get_running_loop().call_later(t * self.scale, self.deliver, frame, self.base + b)
