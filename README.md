# GOOSE

IEC 61850 GOOSE, in your Zelos workspace.

- 📡 **Subscribe to a segment**: pick a network interface; every control block publishing on it appears, nothing to connect to
- 🧩 **One event per control block**: `GOOSE/<goID>` with the header (`stNum`, `sqNum`, `t`, `timeAllowedtoLive`, `test`, `confRev`, ...) and every dataset member as a typed field
- 📄 **Named by SCL**: add the station's `.scd`/`.cid` and members read `ldInst/lnName.doName.daName`; without it they are `d00`, `d01`, ...
- 🩺 **Health per control block**: `stnum_gap`, `sqnum_gap`, `tal_expired`, so a lost or late publisher shows up as a signal
- 📁 **Open a pcap**: decode `.pcap`/`.pcapng`, plain or gzip/zstd compressed, with no privileges and no NIC
- 🎛️ **Demo**: a bundled one-minute capture, for trying it without a substation
- ⏱️ **One timeline**: trips line up with your Sampled Values, Modbus and sensor data

Read-only by design: this extension never publishes a GOOSE message.

## Granting capture rights

Capturing reads raw frames, which needs one grant per machine. Decoding a file does not.

```bash
uv run zelos-extension-goose check        # when denied, prints the exact command for this machine
sudo /path/to/python -m zelos_packet install-helper
```

- 🔐 **Linux** installs a small privileged helper (`cap_net_raw` only) and a `zelos-packet` group; **macOS** installs a boot-time daemon that puts `/dev/bpf*` in the `access_bpf` group
- 🔁 Log out and back in, then restart the agent: a session's groups are fixed at login
- ✅ `python -m zelos_packet status` says whether capture would work right now
- 🪟 Windows: live capture arrives with zelos-packet's Windows backend; until then use `advanced.replay_pcap`

## Quick start

```bash
zelos extensions install goose
zelos extensions start goose --config '{"interfaces": [{"interface": "eth0"}]}'
```

If the rights above are missing, the extension stops on start and logs the exact command to fix it.

Decoding a file needs no privileges and no NIC. It plays once at the capture's pace, then the extension exits:

```bash
zelos extensions start goose --config '{"advanced": {"replay_pcap": "station.pcapng", "replay_scl": "station.scd"}}'
```

Control blocks appear in the tree under **GOOSE → goID**; drag one into the workspace to plot its
members. Per-frame rows are under **GOOSE → your interface → goose**.

## Try it without hardware

A one-minute capture ships with the extension: two publishers, one VLAN-tagged, tripping and resetting.

- **App**: run `GOOSE/demo_capture_path`, paste the path into **Advanced → Replay PCAP File**, save, start
- **CLI**: `uv run zelos-extension-goose --demo`

Either way it plays once and the extension exits.

## How it listens

GOOSE is layer-2 multicast (EtherType `0x88B8`, tagged or not). The interface is always put in
**promiscuous mode**: without it the NIC drops every frame, so this is not a setting. A capture filter
keeps everything else on the station bus (Sampled Values, IP) out of the trace.

| Event | One row per | Fields |
| --- | --- | --- |
| `GOOSE/<goID>` | GOOSE message of that control block | IEC 61850-8-1 names as on the wire: `appid`, `gocbRef`, `timeAllowedtoLive`, `datSet`, `goID`, `t`, `stNum`, `sqNum`, `simulation`, `confRev`, `ndsCom`, `numDatSetEntries`; then one field per dataset member (SCL name, else `d00`, `d01`, ... with the ASN.1 type in the description); then `src_mac`, `vlan_id`, `stnum_gap`, `sqnum_gap`, `tal_expired` |
| `GOOSE/<interface>/goose` | GOOSE frame on that interface | the header fields above, `goID`, and `malformed` |
| `GOOSE/<interface>/packets`, `stats` | captured frame, capture tick | as the Packet extension |

- the event time is the capture time of the frame; the publisher's `t` is a field
- a control block without a `goID` is named by its `gocbRef`
- members are typed from the wire (boolean, bit string, integer, float, UTC time, visible string); an SCL refines the type and names them
- `stnum_gap`/`sqnum_gap` is the number of messages skipped since the previous one; `tal_expired` is true when the previous message's `timeAllowedtoLive` had passed

## Settings

| Setting | Default | |
| --- | --- | --- |
| `interfaces[].interface` | – | NIC to subscribe on |
| `interfaces[].name` | interface name | Names this interface's branch in the tree |
| `interfaces[].scl` | – | SCD/CID file to name and type dataset members by |
| `advanced.prefix` | `GOOSE` | Trace source for per-frame rows; clear it to give each interface its own. Control blocks always sit under `GOOSE/<goID>` |
| `advanced.replay_pcap` | – | Decode this `.pcap`/`.pcapng` (plain or `.gz`/`.zst`) instead of capturing; plays once, then exits. `interfaces` is ignored |
| `advanced.replay_scl` | – | SCD/CID file for the replayed capture's publishers |
| `advanced.log_level` | `INFO` | |

## Actions

| Action | |
| --- | --- |
| `GOOSE/list_interfaces` | NICs on the machine running the agent |
| `GOOSE/check_permissions` | Can we capture? If not, the exact fix |
| `GOOSE/list_gocbs` | Every control block seen: goID, gocbRef, APPID, publisher, stNum/sqNum, last heard |
| `GOOSE/get_status` | Per-interface capture and decoder counters (drops, malformed, gaps, expired) |
| `GOOSE/get_snapshot` | Last header and dataset values of every control block, no bus I/O |
| `GOOSE/convert_pcap` | Convert a pcap to `.trz`, optionally with an SCL. Runs without the extension started |
| `GOOSE/demo_capture_path` | Path of the bundled demo capture, for `advanced.replay_pcap`. Runs without the extension started |

## CLI

```bash
uv run zelos-extension-goose interfaces                       # list NICs
uv run zelos-extension-goose check                            # probe permissions
uv run zelos-extension-goose capture eth0 --scl station.scd   # subscribe, no app config
uv run zelos-extension-goose replay station.pcapng            # stream a file to the agent once, paced
uv run zelos-extension-goose convert station.pcapng.gz        # write station.trz, no agent needed
uv run zelos-extension-goose --demo                           # the bundled capture, played once
```

`capture`, `replay` and `convert` take `--scl` and `--prefix`.

## Links

- [Documentation](https://docs.zeloscloud.io)
- [Issues](https://github.com/zeloscloud/zelos-extension-goose/issues)

MIT. See [LICENSE](LICENSE).
