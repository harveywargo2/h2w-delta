import uuid
import delta.delta2stix as d2s


def sco_unique_uuid5(hash_string: str):
    output = uuid.uuid5(d2s.sco_namespace, hash_string)

    return output

