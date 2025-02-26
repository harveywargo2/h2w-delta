import pandas as pd
import delta2.stix as d2s
import uuid
import stix2
import os


_path = os.path.dirname(os.path.abspath(__file__))
sheet_name = os.path.join(_path, 'winlol_any_patterns.xlsx')


def winlol_any_plib():
    stix_list = []
    df1 = pd.read_excel(sheet_name)

    for index, row in df1.iterrows():

        x = d2s.XDeltaPid(
            id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, str(df1.loc[index, 'delta_pid']))),
            created_by_ref=d2s.delta_identity,
            created="2025-01-01T00:00:00.000Z",
            modified="2025-01-01T00:00:00.000Z",
            name=df1.loc[index, 'name'],
            description=df1.loc[index, 'description'],
            object_marking_refs=[stix2.TLP_WHITE],
            labels=[],
            x_delta_pid=df1.loc[index, 'delta_pid'],
            x_delta_category=df1.loc[index, 'delta_category'],
            x_delta_info={
                "pattern": df1.loc[index, 'delta_pattern'],
                "mitre_technique": df1.loc[index, 'mitre_technique'],
                "mitre_sub_technique": df1.loc[index, 'mitre_sub_technique'],
                "procedure": df1.loc[index, 'delta_method']
            }
        )

        stix_list.append(x)


    return stix_list

