"""Builds the bundled demo capture, `goose-demo.pcap`, from bytes.

The frames are hand-encoded here (BER, IEC 61850-8-1 clause 18) so what the
demo replays is visible in this file. One minute of two publishers, one
VLAN-tagged, each retransmitting at 1 s with a burst after every state change.

Regenerate with `just demo-pcap`; a test holds the committed file to this output.
"""

from __future__ import annotations

import struct

from . import DEMO_PCAP

GOOSE_MULTICAST = bytes.fromhex("010ccd010001")
PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1

#: Capture start, in the pcap and in every UtcTime.
T0_US = 1_700_000_000 * 1_000_000
DURATION_US = 60_000_000
HEARTBEAT_US = 1_000_000
#: Retransmissions after a change: 4, 8, 16 and 32 ms apart, then the heartbeat.
BURST_US = (0, 4_000, 12_000, 28_000, 60_000)


def _ber(tag: int, body: bytes) -> bytes:
    """One BER TLV; lengths here never exceed the long form's one extra byte."""
    n = len(body)
    length = bytes([n]) if n < 0x80 else bytes([0x81, n]) if n < 0x100 else b"\x82" + n.to_bytes(2)
    return bytes([tag]) + length + body


def _int(tag: int, value: int) -> bytes:
    size = max(1, (value.bit_length() + 8) // 8)
    return _ber(tag, value.to_bytes(size, "big", signed=True))


def _utc_time(epoch_us: int) -> bytes:
    """IEC 61850 UtcTime: 4-byte seconds, 3-byte fraction, 1-byte quality."""
    seconds, us = divmod(epoch_us, 1_000_000)
    fraction = us * (1 << 24) // 1_000_000
    return struct.pack(">I", seconds) + fraction.to_bytes(3, "big") + b"\x0a"


def goose_pdu(
    *,
    gocb_ref: str,
    dat_set: str,
    go_id: str,
    st_num: int,
    sq_num: int,
    t_us: int,
    members: list[bytes],
    tal_ms: int = 2000,
    conf_rev: int = 1,
) -> bytes:
    body = (
        _ber(0x80, gocb_ref.encode())
        + _int(0x81, tal_ms)
        + _ber(0x82, dat_set.encode())
        + _ber(0x83, go_id.encode())
        + _ber(0x84, _utc_time(t_us))
        + _int(0x85, st_num)
        + _int(0x86, sq_num)
        + _ber(0x87, b"\x00")  # test
        + _int(0x88, conf_rev)
        + _ber(0x89, b"\x00")  # ndsCom
        + _int(0x8A, len(members))
        + _ber(0xAB, b"".join(members))
    )
    return _ber(0x61, body)


#: Data members (IEC 61850-8-1 table 85 tags): boolean, bit-string quality, int32.
def boolean(value: bool) -> bytes:
    return _ber(0x83, b"\x01" if value else b"\x00")


def quality_good() -> bytes:
    return _ber(0x84, b"\x03\x00\x00")  # 3 unused bits, all zero: good


def int32(value: int) -> bytes:
    return _ber(0x85, value.to_bytes(4, "big", signed=True))


def goose_frame(appid: int, pdu: bytes, *, src: bytes, vlan: int | None = None) -> bytes:
    eth = GOOSE_MULTICAST + src
    if vlan is not None:
        eth += b"\x81\x00" + struct.pack(">H", 0x8000 | vlan)  # PCP 4
    length = 8 + len(pdu)
    return eth + b"\x88\xb8" + struct.pack(">HHHH", appid, length, 0, 0) + pdu


def publisher_frames(
    *,
    start_us: int,
    st_num: int,
    members: list[bytes],
    changes: list[tuple[int, list[bytes]]],
    appid: int,
    src: bytes,
    vlan: int | None,
    gocb: str,
    ds: str,
    go_id: str,
) -> list[tuple[int, bytes]]:
    """(offset us, frame) for one publisher: a heartbeat from `start_us`, and at
    each change stNum + 1, sqNum back to 0, `t` stamped, and a burst."""
    frames: list[tuple[int, bytes]] = []
    sq_num, t_us, at = 0, 0, start_us
    pending = list(changes)

    def send(when: int) -> None:
        nonlocal sq_num
        pdu = goose_pdu(
            gocb_ref=gocb,
            dat_set=ds,
            go_id=go_id,
            st_num=st_num,
            sq_num=sq_num,
            t_us=T0_US + t_us,
            members=members,
        )
        frames.append((when, goose_frame(appid, pdu, src=src, vlan=vlan)))
        sq_num += 1

    while at < DURATION_US:
        if pending and pending[0][0] <= at:
            t_us, members = pending.pop(0)
            st_num, sq_num = st_num + 1, 0
            for delay in BURST_US:
                send(t_us + delay)
            at = t_us + BURST_US[-1] + HEARTBEAT_US
        else:
            send(at)
            at += HEARTBEAT_US
    return frames


def demo_frames() -> list[tuple[int, bytes]]:
    """(offset us, frame) for the demo, in capture order."""
    # A: breaker trip, untagged. Trips at 12 s, resets at 30 s, trips again at 45 s.
    trip = publisher_frames(
        start_us=0,
        st_num=1,
        members=[boolean(False), quality_good()],
        changes=[
            (12_000_000, [boolean(True), quality_good()]),
            (30_000_000, [boolean(False), quality_good()]),
            (45_000_000, [boolean(True), quality_good()]),
        ],
        appid=0x1000,
        src=bytes.fromhex("0200000000a1"),
        vlan=None,
        gocb="P1Q1BCU/LLN0$GO$gcbTrip",
        ds="P1Q1BCU/LLN0$dsTrip",
        go_id="P1Q1BCU_Trip",
    )
    # B: interlock and feeder current, VLAN 5. Follows A 10 ms later.
    intl = publisher_frames(
        start_us=500_000,
        st_num=7,
        members=[boolean(True), quality_good(), int32(1200)],
        changes=[
            (12_010_000, [boolean(False), quality_good(), int32(0)]),
            (30_010_000, [boolean(True), quality_good(), int32(1180)]),
            (45_010_000, [boolean(False), quality_good(), int32(0)]),
        ],
        appid=0x1001,
        src=bytes.fromhex("0200000000b2"),
        vlan=5,
        gocb="P1Q2BCU/LLN0$GO$gcbIntl",
        ds="P1Q2BCU/LLN0$dsIntl",
        go_id="P1Q2BCU_Intl",
    )
    return sorted(trip + intl, key=lambda f: f[0])


def pcap_bytes(frames: list[tuple[int, bytes]]) -> bytes:
    """A classic (little-endian, microsecond) pcap of `frames`."""
    out = [struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)]
    for offset_us, data in frames:
        seconds, us = divmod(T0_US + offset_us, 1_000_000)
        out.append(struct.pack("<IIII", seconds, us, len(data), len(data)) + data)
    return b"".join(out)


def demo_pcap_bytes() -> bytes:
    return pcap_bytes(demo_frames())


if __name__ == "__main__":
    DEMO_PCAP.write_bytes(demo_pcap_bytes())
    print(f"{DEMO_PCAP}: {DEMO_PCAP.stat().st_size} bytes")
