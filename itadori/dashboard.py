"""Live dashboard. Runs the real protocol stack twice (plain mesh vs Itadori) in one process and serves a web UI.
Standard library only. Usage: python -m itadori.dashboard [--scale 0.2] [--port 8080]"""
import argparse, asyncio, json, pathlib, time
from urllib.parse import parse_qs, urlparse
from .network import Network

ROOT = pathlib.Path(__file__).resolve().parent.parent / 'dashboard'
KINDS = ('crash', 'cut', 'degrade', 'malicious')

class Dashboard:
    def __init__(self, scale=0.2): self.scale = scale
    async def start(self):
        self.nets = [Network('plain', self.scale), Network('itadori', self.scale)]
        for n in self.nets: await n.start()
        self.t0 = time.monotonic(); self.samples = [[], []]; self.log = []
        self.task = asyncio.get_running_loop().create_task(self.sampler())
    async def stop(self):
        self.task.cancel()
        for n in self.nets: await n.stop()
    async def reset(self): await self.stop(); await self.start()
    def now(self): return (time.monotonic() - self.t0) / self.scale
    async def sampler(self):
        while True:
            for i, n in enumerate(self.nets):
                self.samples[i].append((self.now(), *n.snapshot())); del self.samples[i][:-200]
            await asyncio.sleep(self.scale)

    def trigger_sos(self, origin=None, code='TRAPPED', victims=1):
        """Trigger an emergency SOS frame from a survivor node in Itadori network."""
        inet = self.nets[1]
        target = int(origin) if origin is not None else (7 if len(inet.nodes) > 7 else 1)
        ok = inet.send_sos(target, code_str=code, victims=victims)
        if ok:
            msg = f'🚨 SOS Broadcast from Node {target}: {code} ({victims} victims) – priority queue preemption'
            self.log.append((self.now(), msg))
            return msg
        return 'Failed to send SOS'

    def run_scenario(self, name):
        """Run disaster scenario on both networks."""
        res_msgs = []
        for net in self.nets:
            r = net.run_scenario(name)
            res_msgs.append(r['status'])
        msg = f'🌪️ Scenario [{name.upper()}]: ' + res_msgs[-1]
        self.log.append((self.now(), msg))
        return msg

    def export_report(self):
        """Return the incident response & forensics report."""
        inet = self.nets[1]
        return inet.export_incident_report()

    def apply(self, kind, node=None):
        """Inject the same fault into both networks. With no node given, hit the busiest relay."""
        a = self.nets[0]
        if kind == 'corrupt_ledger':
            # Tamper with one itadori node's local ledger block for the demo
            inet = self.nets[1]
            target = int(node) if node is not None else None
            for n in inet.nodes:
                if n.chain and n.chain.height >= 1:
                    if target is None or n.id == target:
                        try:
                            n.chain.tamper(1)
                            msg = f'Ledger block 1 tampered on node {n.id} – verify_chain now fails; resync triggered'
                            self.log.append((self.now(), msg)); return msg
                        except Exception as e:
                            return str(e)
            return 'No node has a sealed ledger block yet'
        if kind not in KINDS: return 'unknown fault'
        ok = {n.id for n in a.nodes if n.id != 0 and n.alive and n.behavior == 'honest' and a.air.txq.get(n.id, 1) == 1}
        if node not in ok: node = a.busiest() if a.busiest() in ok else next(iter(sorted(ok)), None)
        if node is None: return 'no eligible node left'
        nh = a.nodes[node].next_hop()
        if kind == 'cut' and nh is None: return 'node has no route to cut'
        for net in self.nets:
            {'crash': lambda: net.crash(node), 'degrade': lambda: net.degrade(node), 'malicious': lambda: net.malicious(node),
             'cut': lambda: net.cut(node, nh)}[kind]()
        msg = {'crash': f'Node {node} crashed', 'degrade': f'Node {node} transmitter degraded', 'malicious': f'Node {node} turned malicious (tampers with relayed data)',
               'cut': f'Link {node}-{nh} cut'}[kind]
        self.log.append((self.now(), msg)); return msg

    def state(self, since=0.0):
        t = self.now(); nets = []
        for i, net in enumerate(self.nets):
            gw, s = net.nodes[0], self.samples[i]
            if s:
                base = next((x for x in s if x[0] >= t - 30), s[0]); last = s[-1]
                sent = max(1, last[1] - base[1]); ok, bad = last[2] - base[2], last[3] - base[3]
            else: sent, ok, bad = 1, 0, 0
            resilience = net.get_resilience()
            net_data = {'mode': net.cfg.mode, 'delivery': max(0, min(1, ok / sent)), 'corrupted': max(0, min(1, bad / sent)),
                'resilience': resilience,
                'nodes': [{'id': n.id, 'x': net.positions[n.id][0] / 3, 'y': net.positions[n.id][1] / 2, 'alive': n.alive, 'bad': n.behavior == 'tamper',
                           'weak': net.air.txq.get(n.id, 1) < 1, 'quar': n.id in gw.quarantined, 'gw': n.id == 0, 'battery': round(getattr(n, 'battery', 100.0), 1),
                           'is_cut_vertex': n.id in resilience.get('cut_vertices', []),
                           'next': n.next_hop() if n.alive else None} for n in net.nodes],
                'links': [[a, b] for (a, b) in net.air.q if a < b and (a, b) not in net.air.cut],
                'bridges': resilience.get('bridges', []),
                'frames': [[round(w, 2), snd, ty, nh] for ft, snd, ty, nh in list(net.air.recent) for w in [(ft - self.t0) / self.scale] if w > since and ty in (3, 4, 5)]}
            # Ledger & SOS state (itadori only)
            if net.cfg.mode == 'itadori':
                net_data['ledger'] = net.ledger_state()
                # Per-node ledger details for the panel
                per_node = []
                for n in net.nodes:
                    if n.chain:
                        per_node.append({
                            'id': n.id,
                            'height': n.chain.height,
                            'head': n.chain.head().block_hash[:8].hex(),
                            'intact': n.chain.is_intact(),
                        })
                net_data['ledger']['nodes'] = per_node
                net_data['sos_log'] = getattr(gw, 'sos_log', [])[-5:]
            nets.append(net_data)
        ev = [(w, m) for w, m in self.log] + [((e[0] - self.t0) / self.scale, e[1]) for e in self.nets[1].nodes[0].events]
        return {'t': round(t, 2), 'nets': nets, 'log': [[round(w, 1), m] for w, m in sorted(ev)[-8:]][::-1]}

async def serve(dash, port, host='127.0.0.1'):
    async def handle(r, w):
        try:
            line = (await r.readline()).decode()
            if not line: return
            method, target, _ = line.split(' ', 2)
            while (await r.readline()).strip(): pass
            u = urlparse(target); q = {k: v[0] for k, v in parse_qs(u.query).items()}
            code, ctype, body = 404, 'text/plain', b'not found'
            if u.path == '/state': code, ctype, body = 200, 'application/json', json.dumps(dash.state(float(q.get('since', 0)))).encode()
            elif u.path == '/fault' and method == 'POST': code, ctype, body = 200, 'application/json', json.dumps({'msg': dash.apply(q.get('kind'), int(q['node']) if 'node' in q else None)}).encode()
            elif u.path == '/sos' and method == 'POST': code, ctype, body = 200, 'application/json', json.dumps({'msg': dash.trigger_sos(q.get('node'), q.get('code', 'TRAPPED'), int(q.get('victims', 1)))}).encode()
            elif u.path == '/scenario' and method == 'POST': code, ctype, body = 200, 'application/json', json.dumps({'msg': dash.run_scenario(q.get('name', 'flood'))}).encode()
            elif u.path == '/report': code, ctype, body = 200, 'application/json', json.dumps(dash.export_report(), indent=2).encode()
            elif u.path == '/reset' and method == 'POST': await dash.reset(); code, ctype, body = 200, 'application/json', b'{}'
            elif u.path in ('/', '/index.html'): code, ctype, body = 200, 'text/html; charset=utf-8', (ROOT / 'index.html').read_bytes()
            w.write(f'HTTP/1.1 {code} OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n'.encode() + body)
            await w.drain()
        except Exception: pass
        finally: w.close()
    return await asyncio.start_server(handle, host, port)

async def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--scale', type=float, default=0.2, help='real seconds per protocol second'); ap.add_argument('--port', type=int, default=8080)
    a = ap.parse_args(); d = Dashboard(a.scale); await d.start(); srv = await serve(d, a.port)
    print(f'Itadori dashboard on http://127.0.0.1:{a.port}  (scale {a.scale}: 1 real second = {1 / a.scale:.0f} protocol seconds)')
    async with srv: await srv.serve_forever()

if __name__ == '__main__':
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
