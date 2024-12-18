from delta.generators.os_windows.comsvcs.comsvcs import (bundle__comsvcs_p0000)
import json



bundle__comsvcs = bundle__comsvcs_p0000()
print(bundle__comsvcs)

with open('bundle-comsvcs-delta.json', 'w') as file:
    json.dump(bundle__comsvcs.serialize(), file)