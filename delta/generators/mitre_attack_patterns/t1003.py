import json
import delta.generators.mitre_attack_patterns as map


ap_list = map.list_mitre_enterprise_attack_patterns_objects()


def list_t1003_enterprise_attack_patterns():
    t1003_list = []

    for item in ap_list:
        if 'T1003' in str(item['external_references'][0]):
            t1003_list.append(item)

    return t1003_list


def attack_pattern_t1003():
    for item in list_t1003_enterprise_attack_patterns():
        if str(item['external_references'][0]['external_id']) == 'T1003':
            output = item

    return output


def attack_pattern_t1003001():
    for item in list_t1003_enterprise_attack_patterns():
        if str(item['external_references'][0]['external_id']) == 'T1003.001':
            output = item

    return output


def attack_pattern_t1003002():
    for item in list_t1003_enterprise_attack_patterns():
        if str(item['external_references'][0]['external_id']) == 'T1003.002':
            output = item

    return output


def attack_pattern_t1003003():
    for item in list_t1003_enterprise_attack_patterns():
        if str(item['external_references'][0]['external_id']) == 'T1003.003':
            output = item

    return output


def attack_pattern_t1003004():
    for item in list_t1003_enterprise_attack_patterns():
        if str(item['external_references'][0]['external_id']) == 'T1003.004':
            output = item

    return output


def attack_pattern_t1003005():
    for item in list_t1003_enterprise_attack_patterns():
        if str(item['external_references'][0]['external_id']) == 'T1003.005':
            output = item

    return output


def attack_pattern_t1003006():
    for item in list_t1003_enterprise_attack_patterns():
        if str(item['external_references'][0]['external_id']) == 'T1003.006':
            output = item

    return output


def attack_pattern_t1003007():
    for item in list_t1003_enterprise_attack_patterns():
        if str(item['external_references'][0]['external_id']) == 'T1003.007':
            output = item

    return output


def attack_pattern_t1003008():
    for item in list_t1003_enterprise_attack_patterns():
        if str(item['external_references'][0]['external_id']) == 'T1003.008':
            output = item

    return output

