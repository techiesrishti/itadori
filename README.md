# Itadori 

A Byzantine-resilient, self-healing LoRa mesh protocol, written as real networking code. Nodes are independent asyncio endpoints, each with its own UDP socket. They exchange real binary frames, authenticate them, route with measured link quality, detect misbehaving relays, and vote to quarantine them with signed PBFT-style consensus.

**What is real and what is emulated**

| Layer | Status |
|---|---|
| Frame format (255-byte LoRa limit), HMAC tags, Ed25519 signatures | Real |
| Hello beacons, link-quality estimation, link-state flooding, routing | Real, driven by measured delivery |
| Overhearing watchdog, signed accusations, quorum consensus (f=1 in a 4-node cluster) | Real |
| Time on air (Semtech formula), range, loss, half-duplex transmit | Emulated in `itadori/air.py` |
| RF propagation, interference, collisions, duty-cycle limits | Not modelled |
| Hash-chained decision ledger, commit-signature finality, chain sync between nodes | Real |

The emulated radio is the only part that needs hardware. To run on real radios, replace the UDP `sendto` and receive path in `Node` with an SX126x driver. The protocol code above it does not change.

## Run

```
pip install -r requirements.txt
python -m unittest -v tests.test_itadori    # 9 tests, about 35 s
python demo.py                              # four faults, plain mesh vs Itadori, about 1 min
python -m itadori.dashboard                 # live browser dashboard
```

Timers run in "protocol seconds". `Config.scale` converts them to wall time (default 0.04, so 25x faster than real time). Airtime is scaled the same way.

## Dashboard

```
python -m itadori.dashboard            # then open http://127.0.0.1:8080
python -m itadori.dashboard --scale 1  # real-time speed, slower and easier to follow
```

Two live networks run side by side, the plain mesh and Itadori, and both receive the same fault. The page draws what the nodes are actually doing: each node's current route to the gateway, real data frames in flight, signed consensus messages as amber rings, and quarantines as dashed rings. Buttons crash a relay, cut a link, degrade a transmitter or turn a relay malicious. Click a node to target it, otherwise the busiest relay is hit. The server uses only the standard library and binds to localhost.

## How it works

- **Routing.** Each node measures delivery of its neighbours' hello beacons, floods link-state advertisements, and routes to the gateway with cost `1/quality + 0.04 * neighbour load`. A link counts only if both ends report it. A degraded transmitter shows up as lower measured quality, so traffic moves away without any special case.
- **Authentication.** Data frames carry a hop MAC (network key) and an end-to-end MAC from the originator, verified by the gateway. Control messages are signed with Ed25519, so an insider cannot forge another node's accusation or vote.
- **Detection.** After forwarding, a node listens for the relay to retransmit. Any node that overhears a packet go in and come out changed signs an accusation.
- **Quarantine.** The primary (gateway) proposes quarantine once two distinct signed accusers exist. Cluster members vote only if they independently hold the same evidence, then prepare and commit. Three of four commits quarantine the node everywhere, so one silent or lying cluster member cannot block or force a decision.
- **Plain baseline.** `mode='plain'` uses hop-count routing with no watchdog and no trust, like a mesh that trusts every node.

## Ledger

Every quarantine decision the cluster commits is recorded in a permissioned, hash-chained ledger. This is not a public blockchain: there is no mining, no tokens and no external chain. It is a tamper-evident audit trail that a response agency could verify after an incident.

- **What goes in a block.** The decision (which node was quarantined), the distinct accusers, and the consensus sequence number. Each block holds the hash of the previous one.
- **Finality.** A block is valid only if it links to the previous hash and carries valid Ed25519 commit signatures from a quorum (3 of the 4 cluster members). One Byzantine cluster member cannot forge, fork or censor a block.
- **No block broadcasting.** Every node builds the same block from the committed decision, so full blocks never cross the radio. Nodes gossip a short head hash and height, and a node that is behind requests the missing blocks, which are fragmented to fit the 255-byte LoRa frame limit.
- **Verification.** Each node checks the whole chain when it loads from disk and refuses a broken one. A node whose chain is corrupted detects it and resyncs from its peers.
- **Dashboard.** Each network shows chain height, head hash, and whether all live nodes agree. A "Corrupt a block" button tampers with one node's chain so you can watch verification fail and the node recover.

## Results (one run per cell, protocol seconds)

Fault injected at the busiest relay; "After" is measured over 60 s starting 40 s after the fault. Single runs are noisy, so expect swings of about 10 points between runs.

| Fault | Network | Before | After | Corrupted after | Nodes that quarantined it |
|---|---|---|---|---|---|
| Node crash | Plain mesh | 93% | 87% | 0% | n/a |
| Node crash | Itadori | 92% | 94% | 0% | 0 |
| Link loss | Plain mesh | 89% | 87% | 0% | n/a |
| Link loss | Itadori | 100% | 100% | 0% | 0 |
| Degraded node | Plain mesh | 85% | 78% | 0% | n/a |
| Degraded node | Itadori | 85% | 89% | 0% | 0 |
| Malicious node | Plain mesh | 100% | 72% | 23% | n/a |
| Malicious node | Itadori | 89% | 83% | 0% | 8 |

The consistent signal is the malicious node: the plain mesh keeps delivering corrupted data, while Itadori is quarantined by every node and corruption drops to zero. The crash, link and degraded cases are within noise of each other. Run them several times before quoting numbers.

## Limits, stated plainly

- No view change: if the primary (gateway) is Byzantine, consensus stalls. The gateway is assumed trusted.
- A relay that silently drops packets is not detected, only one that alters them. Sinkhole attacks (lying about link quality in advertisements) are not defended.
- Two accusers are required, so a relay with fewer than two watchers cannot be convicted. The overhearing watchdog usually supplies them in a dense mesh, but a thin one may not.
- Keys are provisioned in the test harness. A real deployment needs key distribution and revocation.
- Collisions and duty-cycle limits are not modelled, so channel capacity is optimistic.
- The 8-node topology is small and fixed, and results are not averaged over many layouts.
- The ledger has no proof of work. Its finality is only as strong as the cluster quorum, so if 2 of the 4 cluster members are compromised, it can be forged.
- It records decisions, not raw traffic, and it is tamper-evident rather than "immutable" or "trustless".
- Ledger sync shares the same low-bandwidth channel as everything else, so catching up after a long outage is slow.