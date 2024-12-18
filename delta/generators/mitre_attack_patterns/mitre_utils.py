import requests
import json
import os


url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json'
mitre_dir = os.path.abspath(__file__)

def get_mitre_attack_base_bundle():

    response = requests.get(url)
    output = json.loads(response.text)

    return output


def update_base_bundle_dump():
    with open('bundle__mitre_enterprise_attack_base.json', 'w') as json_file:
        json.dump(get_mitre_attack_base_bundle(), json_file)

    return


def list_mitre_enterprise_attack_patterns_objects():
    ap_list = []

    with open(os.path.join(os.path.dirname(mitre_dir), 'bundle__mitre_enterprise_attack_base.json'), 'r') as file:
        data = json.load(file)

    ap_data = data['objects']

    for item in ap_data:
        if 'type' in item and item['type'] == 'attack-pattern':
            ap_list.append(item)

    return ap_list

