import requests
import json


url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json'

def get_mitre_attack_base_bundle():

    response = requests.get(url)
    output = json.loads(response.text)

    return output


def update_base_bundle_dump():
    with open('bundle__mitre_attack_base.json', 'w') as json_file:
        json.dump(get_mitre_attack_base_bundle(), json_file)

    return

update_base_bundle_dump()


def get_mitre_attack_patterns_index():
    ap_list = []

    with  open('bundle__mitre_attack_base.json', 'r') as file:
        data = json.load(file)

    ap_data = data['objects']

    for item in ap_data:
        if 'type' in item and item['type'] == 'attack-pattern':
            ap_list.append(item)

    return ap_list

print(get_mitre_attack_patterns_index())