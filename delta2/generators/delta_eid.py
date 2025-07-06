from delta2.common import (base_path, delta_namespace, delta_identity, default_timestamp, x_delta_eid)
from delta2.stix import XDeltaEvidenceId
import os
import uuid
import pandas as pd
import stix2
import json
import numpy as np


lib_e = os.path.join(base_path, 'lib_evidence')

# delta_eid excel sheets
ransom = os.path.join(lib_e, 'eid-ransom.xlsx')


def xls2stx_ransom_process_create():
    stix_list = []
    df1 = pd.read_excel(ransom, sheet_name='process_create')
    df1 = df1.replace({np.nan: None})

    # Add error handling to pinpoint the exact problematic value
    def parse_json_safely(json_string):
        if pd.isna(json_string) or json_string is None:
            return None  # Or a default empty dictionary, depending on your needs
        try:
            return json.loads(json_string)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            print(f"Problematic string: '{json_string}'")
            return None  # Return None or raise the error if you want to stop execution

    df1['parse_json'] = df1['ns_meta'].apply(parse_json_safely)

    df1['eid_date'] = df1['parse_json'].apply(lambda x: x.get('date', 'N/A'))
    df1['eid_url'] = df1['parse_json'].apply(lambda x: x.get('url', 'N/A'))
    df1['tags'] = df1['parse_json'].apply(lambda x: x.get('tags', 'N/A'))

    for index, row in df1.iterrows():

        x = XDeltaEvidenceId(
            id=x_delta_eid + str(uuid.uuid5(delta_namespace, str(df1.loc[index, 'delta_eid']))),
            created_by_ref=delta_identity,
            created=default_timestamp,
            modified=default_timestamp,
            description=df1.loc[index, 'description'],
            object_marking_refs=[stix2.TLP_WHITE],
            labels=[],
            x_delta_evidence_id=df1.loc[index, 'delta_eid'] + '--process_create',
            x_evidence_obj={
                "process_cmdline": df1.loc[index, 'process_cmdline'],
                "initiating_process_cmdline": df1.loc[index, 'initiating_process_cmdline'],
                "process_name": df1.loc[index, 'process_name'],
                "initiating_process_name": df1.loc[index, 'initiating_process_name'],
                "process_path": df1.loc[index, 'process_path'],
                "initiating_process_path": df1.loc[index, 'initiating_process_path'],
                "process_account": df1.loc[index, 'process_account'],
                "object": df1.loc[index, 'object']
            },
            x_evidence_meta={
                "evidence_type": "Reported",
                "evidence_date": df1.loc[index, 'eid_date'],
                "evidence_url": df1.loc[index, 'eid_url'],
                "tags": df1.loc[index, 'tags']
            }
        )
        stix_list.append(x)


    return stix_list


