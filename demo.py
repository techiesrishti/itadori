"""Runs each fault on the plain mesh and on Itadori, over real UDP sockets with an emulated radio. Prints a results table."""
import asyncio, sys
from itadori.network import Network
FAULTS = {'Node crash': lambda n, b: n.crash(b), 'Link loss': lambda n, b: n.cut(b, n.nodes[b].next_hop()),
          'Degraded node': lambda n, b: n.degrade(b), 'Malicious node': lambda n, b: n.malicious(b)}
async def run(mode, fault):
    net = Network(mode); await net.start(); await net.sleep(60)
    before = await net.measure(30); b = net.busiest(); FAULTS[fault](net, b)
    await net.sleep(40); after = await net.measure(60)
    q = sum(b in n.quarantined for n in net.nodes); await net.stop(); return before, after, q, net.air.airtime
async def main():
    rows = ['| Fault | Network | Before | After | Corrupted after | Nodes that quarantined it |', '|---|---|---|---|---|---|']
    for fault in FAULTS:
        for mode in ('plain', 'itadori'):
            b, a, q, _ = await run(mode, fault); print(f'{fault} / {mode}: {a}', file=sys.stderr)
            rows.append(f"| {fault} | {'Plain mesh' if mode == 'plain' else 'Itadori'} | {b['delivery']:.0%} | {a['delivery']:.0%} | {a['corrupted']:.0%} | {q if mode == 'itadori' else 'n/a'} |")
    print('\n'.join(rows))
if __name__ == '__main__': asyncio.run(main())
