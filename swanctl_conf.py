#!/usr/local/bin/python3.8
import re
import json
import sys

IPSEC_CONF = '/var/etc/ipsec/swanctl.conf'

def Parse():
    with open(IPSEC_CONF, 'r') as file:
        text = file.read()

        connections = re.findall(r'con\d+ {[^}]*}', text, re.DOTALL)
        data = {}

        for conn in connections:
            # print('conn:', conn)
            key_match = re.search(r'con(\d+)', conn)
            local_match = re.search(r'local_addrs = ([\d.]+)', conn)
            remote_match = re.search(r'remote_addrs = ([\d.]+)', conn)
            desc_match = re.search(r'# P1 \(ikeid \d+\): (.+)', conn)

            if not key_match or not local_match or not remote_match or not desc_match:
                continue
            key = key_match.group(0)
            local = local_match.group(1)
            remote = remote_match.group(1)
            desc = desc_match.group(1)

            data[key] = {'local': local, 'remote': remote, 'description': desc}
            # print('data[key1]"', data[key], type(data[key]))
        return data

    def get_JSON_format():
    data = Parse()
    lis = []
    conf = ''
    for key, value in data.items():
        lis.append({
            '{#TUNNEL}': key,
            '{#TARGETIP}': value['remote'],
            '{#SOURCEIP}': value['local'],
            '{#DESCRIPTION}': value['description'],
        })
    return json.dumps({'data': lis}, indent=4)

if __name__ == '__main__':
    result = get_JSON_format()
    sys.exit(result)
