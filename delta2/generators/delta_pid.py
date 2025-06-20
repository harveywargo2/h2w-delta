from delta2.common import (base_path, delta_namespace, delta_identity, default_timestamp, x_delta_pid)
from delta2.stix import XDeltaPid
import os
import uuid
import pandas as pd
import stix2


lib_p = os.path.join(base_path, 'lib_patterns')

# delta_pid excel sheets
winlol = os.path.join(lib_p, 'pid-lolwin.xlsx')


def dpid_winlol():
    stix_list = []
    df1 = pd.read_excel(winlol)

    for index, row in df1.iterrows():

        x = XDeltaPid(
            id=x_delta_pid + str(uuid.uuid5(delta_namespace, str(df1.loc[index, 'delta_pid']))),
            created_by_ref=delta_identity,
            created=default_timestamp,
            modified=default_timestamp,
            name=df1.loc[index, 'name'],
            description=df1.loc[index, 'description'],
            object_marking_refs=[stix2.TLP_WHITE],
            labels=[],
            x_delta_pid=df1.loc[index, 'delta_pid'],
            x_pid_ns_obj={
                "delta_pattern": df1.loc[index, 'delta_pattern'],
                "mitre_technique": df1.loc[index, 'atk_tech'],
                "mitre_sub_technique": df1.loc[index, 'atk_subtech'],
                "delta_did": df1.loc[index, 'delta_did'],
                "pid_type": df1.loc[index, 'dpid_type'],
            }
        )
        stix_list.append(x)


    return stix_list

