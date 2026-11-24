"""
Emergency Codebook and Priority SOS messaging for Itadori mesh.

Designed for low-bandwidth LoRa links during search and rescue operations.
Enables victims or frontline responders to transmit essential triage information
in a compact 8-byte payload that bypasses routine telemetry queues.
"""
import struct, time
from typing import NamedTuple, Optional

# Emergency Triage Codebook
TRIAGE_CODES = {
    1: ("CRITICAL_MEDICAL", "Severe injury / triage red / medic needed"),
    2: ("TRAPPED_DEBRIS", "Survivors trapped under collapsed structure"),
    3: ("RISING_FLOOD", "Water rising rapidly / roof refuge required"),
    4: ("FIRE_HAZARD", "Active fire / gas hazard / chemical leak"),
    5: ("SUPPLIES_DEPLETED", "Dehydrated / infant supplies exhausted"),
    6: ("SAFE_CHECKIN", "Group secure / waiting for evacuation"),
}

# Lookup map by friendly keyword or prefix
CODE_MAP = {
    "MEDICAL": 1,
    "CRITICAL_MEDICAL": 1,
    "TRAPPED": 2,
    "TRAPPED_DEBRIS": 2,
    "FLOOD": 3,
    "RISING_FLOOD": 3,
    "FIRE": 4,
    "FIRE_HAZARD": 4,
    "SUPPLIES": 5,
    "SUPPLIES_DEPLETED": 5,
    "SAFE": 6,
    "SAFE_CHECKIN": 6,
}

# Queue Priority Levels (lower number = higher priority in PriorityQueue)
PRIO_EMERGENCY = 0  # Life-safety SOS distress packets
PRIO_CTRL      = 1  # PBFT consensus & Byzantine accusations
PRIO_ROUTING   = 2  # LSAs & Hello beacons
PRIO_DATA      = 3  # Normal background telemetry/app traffic

class SOSMessage(NamedTuple):
    origin: int
    seq: int
    code: int
    code_name: str
    description: str
    victims: int
    lat_offset: float  # latitude offset from base coordinate in degrees
    lon_offset: float  # longitude offset from base coordinate in degrees
    timestamp: float

def pack_sos_payload(code: int, victims: int, lat_offset: float = 0.0, lon_offset: float = 0.0) -> bytes:
    """
    Packs an emergency SOS into 8 compact bytes:
    - 1 byte : triage code (1..6)
    - 1 byte : victim count (1..255)
    - 2 bytes: int16 latitude offset (units of 0.0001 degrees, approx 11m resolution)
    - 2 bytes: int16 longitude offset (units of 0.0001 degrees)
    - 2 bytes: CRC/tag salt
    """
    lat_int = int(round(lat_offset * 10000)) & 0xFFFF
    lon_int = int(round(lon_offset * 10000)) & 0xFFFF
    return struct.pack('>BBHHH', code, min(255, max(1, victims)), lat_int, lon_int, 0x4954)

def unpack_sos_payload(payload: bytes, origin: int = 0, seq: int = 0) -> Optional[SOSMessage]:
    """Unpacks an 8-byte emergency SOS payload."""
    if len(payload) < 8:
        return None
    code, victims, lat_raw, lon_raw, _ = struct.unpack('>BBHHH', payload[:8])
    lat_int = struct.unpack('>h', struct.pack('>H', lat_raw))[0]
    lon_int = struct.unpack('>h', struct.pack('>H', lon_raw))[0]
    name, desc = TRIAGE_CODES.get(code, ("UNKNOWN_CODE", "Unclassified emergency"))
    return SOSMessage(
        origin=origin,
        seq=seq,
        code=code,
        code_name=name,
        description=desc,
        victims=victims,
        lat_offset=lat_int / 10000.0,
        lon_offset=lon_int / 10000.0,
        timestamp=time.time(),
    )
