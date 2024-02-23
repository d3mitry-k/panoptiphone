import base64
import csv
import datetime
import hashlib
import math
import sys
from collections.abc import MutableMapping

from scapy.layers.dot11 import Dot11

sha256key = b'This is SHA256 postfix'

MAX_TIME_DIFF_BURST = datetime.timedelta(0,0,100000)

db = {}
mac_addresses = []
totals = {}
last_frame_time = datetime.datetime(1970,1,1)
devices_seen_this_session = set()
database_already_saved = False


class RawProbe:
    timestamp: datetime.datetime
    mac: str
    rssi: int
    # store as a hex string
    frame: str

    def __init__(self, d=None):
        if d is not None:
            for key, value in d.items():
                setattr(self, key, value)


class HmhProbe:
    timestamp: datetime.datetime
    mac: str
    rssi: int
    # store as a parsed_frame dict
    frame: dict

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def parse_frame(frame):
    """Parse the frame into a dict."""
    packet = Dot11(frame)

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


def parse_probe(probe: RawProbe) -> HmhProbe:
    """Parse the raw probe into a more usable format."""
    parsed_frame = parse_frame(base64.b64decode(probe.frame))
    return HmhProbe(
        timestamp=probe.timestamp,
        mac=probe.mac,
        rssi=probe.rssi,
        frame=parsed_frame
    )


def convert_to_hashed_value(val):
    sha256 = hashlib.sha256()
    sha256.update(val.encode('utf-8'))
    sha256.update(sha256key)
    return sha256.hexdigest()


def calculate_entropy(key, val):
    global db
    nb_devices = float(len(mac_addresses))
    if nb_devices == 0:
        nb_devices = 1
    if key == 'total':
        if val in totals:
            nb_seen = totals[val]
        else:
            nb_seen = 1
        frac = nb_seen/nb_devices
        return -math.log(frac, 2)
    else:
        if key in db and val in db[key]:
            nb_seen = db[key][val]
        else:
            # this device was not added to the database
            nb_seen = 1
        frac = nb_seen/nb_devices
        return -frac * math.log(frac, 2)


def calculate_entropy_total(key):
    e = 0.0
    nb_devices = float(len(mac_addresses))
    if key == 'total':
        nb_devices_with_val = sum(totals.values())
        frac = (nb_devices - nb_devices_with_val)/nb_devices
        e = -frac * math.log(frac, 2)
    else:
        nb_devices_with_val = sum(db[key].values())
        frac = (nb_devices - nb_devices_with_val)/nb_devices
        for val in db[key]:
            e += calculate_entropy(key, val)
        if frac != 0:
            e += -frac * math.log(frac, 2)
    return e


def db_add(key, val):
    global db
    if key in db:
        if val in db[key]:
            db[key][val] += 1
        else:
            db[key][val] = 1.0
    else:
        db[key] = {}
        db[key][val] = 1.0


def calculate_summary():
    global db
    global totals
    if not db:
        print("Empty database")
        return
    fields = {}
    lengths = [len(x) for x in db.keys()]
    if not lengths:
        print("Error: database is empty. Run panoptiphone.sh first!")
        sys.exit(1)
    m = max(lengths)
    sep = " "
    sep2 = " "
    nb_devices = len(mac_addresses)
    print(nb_devices, "devices in the database")
    print("Information element", " " * (m - 19), "|", "Entropy", "|", "Aff dev", "|", "Number of values")
    for field, val in db.items():
        fields[field] = {}
        fields[field]['entropy'] = calculate_entropy_total(field)
        fields[field]['nb_val'] = len(val) + 1 # absence of a value is a value
        fields[field]['aff'] = sum(db[field].values())/float(nb_devices) * 100
    for name, field in sorted(fields.items(), reverse=True, key=lambda t: t[1]['entropy']):
        print(name, " " * (m - len(name)), "| " + sep, "{0:.3f}".format(field['entropy']), "|", "{0:.2f}".format(field['aff']), " |" + sep2 , field['nb_val'])
    print("total", " " * (m - len("total")), "|" + sep, '     ?', "|" + sep2 + "  -   | ", sum(totals.values()))
    nb_unique_devices = 0
    for fingerprint in totals:
        if totals[fingerprint] == 1:
            nb_unique_devices += 1
    print(nb_unique_devices, "devices (" + "{0:.2f}".format(float(nb_unique_devices)/nb_devices * 100) + "%) are unique in the database")


def _flatten_dict_gen(d, parent_key, sep):
    if parent_key == 'Raw':
        return
    if parent_key == '802.11':
        return
    for k, v in d.items():
        if k == 'ID' or k == 'len':
            continue
        subkey = f'{d['ID']}{sep}' if 'ID' in d else ''
        new_key = f'{parent_key}{sep}{subkey}{k}' if parent_key else k
        if isinstance(v, MutableMapping):
            yield from flatten_dict(v, new_key, sep=sep).items()
        else:
            yield new_key, v.strip('\'').replace('\\', '').strip('x').replace('x', ':') if k == 'info' else v
            # yield new_key, v


def flatten_dict(d: MutableMapping, parent_key: str = '', sep: str = ':'):
    return dict(_flatten_dict_gen(d, parent_key, sep))


def new_frame_json(probe):
    global db
    global mac_addresses
    global totals
    total = []
    if '802.11 Information Element' in probe.frame and 'ID' in probe.frame['802.11 Information Element']:
        dot11ie_name = probe.frame['802.11 Information Element']['ID']
        if dot11ie_name in ['SSID', '255']:
            return

    if convert_to_hashed_value(probe.mac) in mac_addresses:
        return

    flat_request = flatten_dict(probe.frame)
    for key, val in flat_request.items():
        db_add(key, val)
        total.append(val)

    print("Adding device to the database")
    mac_addresses.append(convert_to_hashed_value(probe.mac))
    print(probe.mac)

    total_str = ";".join(total)
    if total_str in totals:
        totals[total_str] += 1
    else:
        totals[total_str] = 1


def parse_csv():
    raw_probes = []
    with open(sys.argv[1], newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            raw_probes.append(RawProbe(row))
    probes = list(map(parse_probe, raw_probes))
    for probe in probes:
        new_frame_json(probe)


if __name__ == '__main__':
    parse_csv()
    calculate_summary()
