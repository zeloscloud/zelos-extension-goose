"""The bundled demo capture, for trying the extension without hardware.

`goose-demo.pcap` is committed and shipped. `generate.py` builds it
(`just demo-pcap`), and a test holds the file to that output.
"""

from pathlib import Path

DEMO_PCAP = Path(__file__).resolve().with_name("goose-demo.pcap")
