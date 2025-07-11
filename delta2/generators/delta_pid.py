from delta2.common import (base_path, delta_namespace, delta_identity, default_timestamp, x_delta_pid)
from delta2.stix import XDeltaPatternId
import os
import uuid
import pandas as pd
import stix2
import json
import numpy as np


lib_p = os.path.join(base_path, 'lib_patterns')

# delta_pid excel sheets
winlol = os.path.join(lib_p, 'pid-lolwin.xlsx')
htool = os.path.join(lib_p, 'pid-htool.xlsx')
psploit = os.path.join(lib_p, 'pid-powerview_powersploit.xlsx')


def xls2stx_htool():
    stix_list = []
    df1 = pd.read_excel(htool, sheet_name='htool')
    df1 = df1.replace({np.nan: None})


    df1['parse_json'] = df1['dpid_type'].apply(json.loads)
    df1['pid_case'] = df1['parse_json'].apply(lambda x: x.get('case', 'N/A'))
    df1['pid_type'] = df1['parse_json'].apply(lambda x: x.get('type', 'N/A'))

    for index, row in df1.iterrows():

        x = XDeltaPatternId(
            id=x_delta_pid + str(uuid.uuid5(delta_namespace, str(df1.loc[index, 'delta_pid']))),
            created_by_ref=delta_identity,
            created=default_timestamp,
            modified=default_timestamp,
            name=df1.loc[index, 'name'],
            description=df1.loc[index, 'description'],
            object_marking_refs=[stix2.TLP_WHITE],
            labels=[],
            x_delta_pattern_id=df1.loc[index, 'delta_pid'],
            x_pattern=df1.loc[index, 'delta_pattern'],
            x_pattern_meta={
                "pid_case": df1.loc[index, 'pid_case'],
                "pid_type": df1.loc[index, 'pid_type'],
                "mitre_technique": df1.loc[index, 'atk_tech'],
                "mitre_sub_technique": df1.loc[index, 'atk_subtech'],
                "delta_did": df1.loc[index, 'delta_did']
            }
        )
        stix_list.append(x)


    return stix_list


def xls2stx_netclt():
    stix_list = []
    df1 = pd.read_excel(winlol, sheet_name='netclt')
    df1 = df1.replace({np.nan: None})


    df1['parse_json'] = df1['dpid_type'].apply(json.loads)
    df1['pid_case'] = df1['parse_json'].apply(lambda x: x.get('case', 'N/A'))
    df1['pid_type'] = df1['parse_json'].apply(lambda x: x.get('type', 'N/A'))

    for index, row in df1.iterrows():

        x = XDeltaPatternId(
            id=x_delta_pid + str(uuid.uuid5(delta_namespace, str(df1.loc[index, 'delta_pid']))),
            created_by_ref=delta_identity,
            created=default_timestamp,
            modified=default_timestamp,
            name=df1.loc[index, 'name'],
            description=df1.loc[index, 'description'],
            object_marking_refs=[stix2.TLP_WHITE],
            labels=[],
            x_delta_pattern_id=df1.loc[index, 'delta_pid'],
            x_pattern=df1.loc[index, 'delta_pattern'],
            x_pattern_meta={
                "pid_case": df1.loc[index, 'pid_case'],
                "pid_type": df1.loc[index, 'pid_type'],
                "mitre_technique": df1.loc[index, 'atk_tech'],
                "mitre_sub_technique": df1.loc[index, 'atk_subtech'],
                "delta_did": df1.loc[index, 'delta_did']
            }
        )
        stix_list.append(x)


    return stix_list


def xls2stx_pshell():
    stix_list = []
    df1 = pd.read_excel(winlol, sheet_name='pshell')
    df1 = df1.replace({np.nan: None})


    df1['parse_json'] = df1['dpid_type'].apply(json.loads)
    df1['pid_case'] = df1['parse_json'].apply(lambda x: x.get('case', 'N/A'))
    df1['pid_type'] = df1['parse_json'].apply(lambda x: x.get('type', 'N/A'))

    for index, row in df1.iterrows():

        x = XDeltaPatternId(
            id=x_delta_pid + str(uuid.uuid5(delta_namespace, str(df1.loc[index, 'delta_pid']))),
            created_by_ref=delta_identity,
            created=default_timestamp,
            modified=default_timestamp,
            name=df1.loc[index, 'name'],
            description=df1.loc[index, 'description'],
            object_marking_refs=[stix2.TLP_WHITE],
            labels=[],
            x_delta_pattern_id=df1.loc[index, 'delta_pid'],
            x_pattern=df1.loc[index, 'delta_pattern'],
            x_pattern_meta={
                "pid_case": df1.loc[index, 'pid_case'],
                "pid_type": df1.loc[index, 'pid_type'],
                "mitre_technique": df1.loc[index, 'atk_tech'],
                "mitre_sub_technique": df1.loc[index, 'atk_subtech'],
                "delta_did": df1.loc[index, 'delta_did']
            }
        )
        stix_list.append(x)


    return stix_list


def xls2stx_psploit():
    stix_list = []
    df1 = pd.read_excel(psploit, sheet_name='pview_psploit')
    df1 = df1.replace({np.nan: None})


    df1['parse_json'] = df1['dpid_type'].apply(json.loads)
    df1['pid_case'] = df1['parse_json'].apply(lambda x: x.get('case', 'N/A'))
    df1['pid_type'] = df1['parse_json'].apply(lambda x: x.get('type', 'N/A'))

    for index, row in df1.iterrows():

        x = XDeltaPatternId(
            id=x_delta_pid + str(uuid.uuid5(delta_namespace, str(df1.loc[index, 'delta_pid']))),
            created_by_ref=delta_identity,
            created=default_timestamp,
            modified=default_timestamp,
            name=df1.loc[index, 'name'],
            description=df1.loc[index, 'description'],
            object_marking_refs=[stix2.TLP_WHITE],
            labels=[],
            x_delta_pattern_id=df1.loc[index, 'delta_pid'],
            x_pattern=df1.loc[index, 'delta_pattern'],
            x_pattern_meta={
                "pid_case": df1.loc[index, 'pid_case'],
                "pid_type": df1.loc[index, 'pid_type'],
                "mitre_technique": df1.loc[index, 'atk_tech'],
                "mitre_sub_technique": df1.loc[index, 'atk_subtech'],
                "delta_did": df1.loc[index, 'delta_did']
            }
        )
        stix_list.append(x)


    return stix_list


def xls2stx_reg():
    stix_list = []
    df1 = pd.read_excel(winlol, sheet_name='reg')
    df1 = df1.replace({np.nan: None})


    df1['parse_json'] = df1['dpid_type'].apply(json.loads)
    df1['pid_case'] = df1['parse_json'].apply(lambda x: x.get('case', 'N/A'))
    df1['pid_type'] = df1['parse_json'].apply(lambda x: x.get('type', 'N/A'))

    for index, row in df1.iterrows():

        x = XDeltaPatternId(
            id=x_delta_pid + str(uuid.uuid5(delta_namespace, str(df1.loc[index, 'delta_pid']))),
            created_by_ref=delta_identity,
            created=default_timestamp,
            modified=default_timestamp,
            name=df1.loc[index, 'name'],
            description=df1.loc[index, 'description'],
            object_marking_refs=[stix2.TLP_WHITE],
            labels=[],
            x_delta_pattern_id=df1.loc[index, 'delta_pid'],
            x_pattern=df1.loc[index, 'delta_pattern'],
            x_pattern_meta={
                "pid_case": df1.loc[index, 'pid_case'],
                "pid_type": df1.loc[index, 'pid_type'],
                "mitre_technique": df1.loc[index, 'atk_tech'],
                "mitre_sub_technique": df1.loc[index, 'atk_subtech'],
                "delta_did": df1.loc[index, 'delta_did']
            }
        )
        stix_list.append(x)


    return stix_list


def xls2stx_winlol():
    stix_list = []
    df1 = pd.read_excel(winlol, sheet_name='lolwin')
    df1 = df1.replace({np.nan: None})


    df1['parse_json'] = df1['dpid_type'].apply(json.loads)
    df1['pid_case'] = df1['parse_json'].apply(lambda x: x.get('case', 'N/A'))
    df1['pid_type'] = df1['parse_json'].apply(lambda x: x.get('type', 'N/A'))

    for index, row in df1.iterrows():

        x = XDeltaPatternId(
            id=x_delta_pid + str(uuid.uuid5(delta_namespace, str(df1.loc[index, 'delta_pid']))),
            created_by_ref=delta_identity,
            created=default_timestamp,
            modified=default_timestamp,
            name=df1.loc[index, 'name'],
            description=df1.loc[index, 'description'],
            object_marking_refs=[stix2.TLP_WHITE],
            labels=[],
            x_delta_pattern_id=df1.loc[index, 'delta_pid'],
            x_pattern=df1.loc[index, 'delta_pattern'],
            x_pattern_meta={
                "pid_case": df1.loc[index, 'pid_case'],
                "pid_type": df1.loc[index, 'pid_type'],
                "mitre_technique": df1.loc[index, 'atk_tech'],
                "mitre_sub_technique": df1.loc[index, 'atk_subtech'],
                "delta_did": df1.loc[index, 'delta_did']
            }
        )
        stix_list.append(x)


    return stix_list

