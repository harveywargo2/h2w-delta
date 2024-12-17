import json
import mitre_utils


ap_list = mitre_utils.list_mitre_enterprise_attack_patterns_objects()


def list_t1003_enterprise_attack_patterns():
    t1003_list = []

    for item in ap_list:
        if 'T1003' in str(item['external_references'][0]):
            t1003_list.append(item)
            print(item)

    return t1003_list

