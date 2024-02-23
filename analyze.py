import asyncio
import base64
import binascii
import csv
import datetime
import functools
import os
import time
import sys
from joblib import delayed, Parallel
from scapy.layers.dot11 import Dot11


class RawProbe:
    timestamp: datetime.datetime
    mac: str
    rssi: int
    # store as a hex string
    frame: str


class HmhProbe:
    timestamp: datetime.datetime
    mac: str
    rssi: int
    # store as a parsed_frame dict
    frame: dict

def parse_probe(probe: RawProbe) -> HmhProbe:
    """Parse the raw probe into a more usable format."""
    parsed_frame = parse_frame(probe.frame)
    return HmhProbe(
        timestamp=probe.timestamp,
        mac=probe.mac,
        rssi=probe.rssi,
        frame=parsed_frame,
        pubkey=probe.pubkey,
    )

def parse_frame(frame):
    """Parse the frame into a dict."""
    packet_data = binascii.unhexlify(frame[2:])
    packet = Dot11(packet_data)

    packet_dict = {}
    try:
        for line in packet.show2(dump=True).split("\n"):
            if "###" in line:
                layer = line.strip("#[] ")
                packet_dict[layer] = {}
            elif "=" in line:
                key, val = line.split("=", 1)
                packet_dict[layer][key.strip()] = val.strip()
    except:
        print('error')
    return packet_dict

def parse_probes(probes: list[RawProbe]) -> list[HmhProbe]:
    """Parse the raw probes into a more usable format using joblib."""
    parsed_probes = Parallel(n_jobs=-1)(
        delayed(parse_probe)(probe) for probe in probes
    )
    return parsed_probes

if __name__ == "__main__":
    with open(sys.argv[1], newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            print(row['mac'])
            print(row['timestamp'])
            print(parse_frame(binascii.hexlify(base64.b64decode(row['frame']))))
            print('-----------------------------')


