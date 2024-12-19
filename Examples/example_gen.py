from delta.generators.os_windows.comsvcs.comsvcs import (bundle__comsvcs_stix2_delta_objs)


bundle__comsvcs = bundle__comsvcs_stix2_delta_objs()
bundle_comsvcs_json = bundle__comsvcs.serialize()

with open('bundle-comsvcs-delta.json', 'w') as file:
    file.write(bundle_comsvcs_json)
