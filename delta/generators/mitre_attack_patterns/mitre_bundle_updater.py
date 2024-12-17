import requests
import json


url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json'


def get_mitre_attack_pattern_bundle():

    response = requests.get(url)

    output = json.loads(response.text)

    return output


with open('bundle__mitre_attack_patterns.json', 'w') as json_file:
    json.dump(get_mitre_attack_pattern_bundle(), json_file)

