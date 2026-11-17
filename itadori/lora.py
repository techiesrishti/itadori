"""LoRa physical-layer maths used by the radio emulator."""
import math

def airtime(n_bytes, sf=7, bw=125_000, cr=1, preamble=8, crc=True):
    """Time on air in seconds (Semtech formula, explicit header). 32 bytes at SF7/125 kHz is about 72 ms."""
    t_sym = (2 ** sf) / bw
    de = 1 if (sf >= 11 and bw == 125_000) else 0
    num = 8 * n_bytes - 4 * sf + 28 + (16 if crc else 0)
    n_payload = 8 + max(math.ceil(num / (4 * (sf - 2 * de))) * (cr + 4), 0)
    return (preamble + 4.25 + n_payload) * t_sym

def link_quality(distance, radio_range):
    """Per-frame delivery probability for a link of the given length."""
    return max(0.7, 1 - 0.3 * (distance / radio_range) ** 2)
