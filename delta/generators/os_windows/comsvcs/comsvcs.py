import stix2
from delta.delta2stix import Delta
import delta.delta2stix as d2s
import delta.generators.mitre_attack_patterns as map
import uuid
import pandas as pd
import os


# Common Variables
delta_namespace = d2s.delta_namespace
_delta = "delta--"
_time = d2s.default_timestamp
comsvcs_dir = os.path.abspath(__file__)


# SDO
## SDO Variables
comsvcs_references = [
        {
            "source_name": "strontic",
            "url": "https://strontic.github.io/xcyclopedia/library/comsvcs.dll-67B51761A4BC3BD1B5367A22BA1A5B65.html"
        },
        {
            "source_name": "lolbas",
            "url": "https://lolbas-project.github.io/lolbas/Libraries/comsvcs/"
        },
        {
            "source_name": "JohnLaTxC",
            "url": "https://gist.github.com/JohnLaTwC/3e7dd4cd8520467df179e93fb44a434e"
        },
        {
            "source_name": "Modexp",
            "url": "https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/"
        },
        {
            "source_name": "hawk-eye.io",
            "url": "https://hawk-eye.io/2022/09/tools-used-for-dumping-of-rdpcreds-via-comsvcs-dll/"
        },
        {
            "source_name": "ired.team",
            "url": "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz"
        },
        {
            "source_name": "lsassy",
            "url": "https://github.com/login-securite/lsassy/blob/14d8f8ae596ecf22b449bfe919829173b8a07635/lsassy/dumpmethod/comsvcs.py"
        }
    ]


## Deltas
delta__comsvcs_p0001 = Delta(
    delta="comsvcs_p0001",
    delta_category="single-line-match",
    delta_meta=[],
    id=_delta + str(uuid.uuid5(delta_namespace, "comsvcs_p0001")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Comsvcs.dll Created Dump File of Process with MiniDump",
    description="Comsvcs.dll lolbin used to create IOC of process dumping with MiniDump on Process Command Line",
    pattern="[process:command_line MATCHES 'comsvcs'] AND [process:command_line MATCHES 'MiniDump']",
    pattern_type="stix",
    pattern_version="2.1",
    external_references=comsvcs_references,
    object_marking_refs=[stix2.TLP_WHITE]
)

delta__comsvcs_p0002 = Delta(
    delta="comsvcs_p0002",
    delta_category="single-line-match",
    delta_meta=[],
    id=_delta + str(uuid.uuid5(delta_namespace, "comsvcs_p0002")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Comsvcs.dll Called MiniDumpW Function to Dump Process",
    description="Comsvcs.dll Created Dump File with MiniDumpW (#24) Function of a Process",
    pattern="[process:command_line MATCHES 'comsvcs'] AND ([process:command_line MATCHES '#24'] OR [process:command_line MATCHES '-24'])",
    pattern_type="stix",
    pattern_version="2.1",
    external_references=comsvcs_references,
    object_marking_refs=[stix2.TLP_WHITE]
)

indicator__comsvcs_p0002 = stix2.Indicator(
    id="indicator--" + str(uuid.uuid5(delta_namespace, "comsvcs_p0002")),
    created_by_ref=d2s.delta_identity,
    name="Comsvcs.dll Called MiniDumpW Function to Dump Process",
    pattern="[process:command_line MATCHES 'comsvcs'] AND ([process:command_line MATCHES '#24'] OR [process:command_line MATCHES '-24'])",
    pattern_type="stix",
    pattern_version="2.1",
    valid_from="2018-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE]
)

delta__comsvcs_p0003 = Delta(
    delta="comsvcs_p0003",
    delta_category="single-line-match",
    delta_meta=[],
    id=_delta + str(uuid.uuid5(delta_namespace, "comsvcs_p0003")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Comsvcs.dll Created a File",
    description="Comsvcs.dll creating a file can indicate a process memory dump",
    pattern="([image:path MATCHES 'comsvcs'] OR [parent_process:commandline MATCHES 'comsvcs'] AND [file:action MATCHES 'create'])",
    pattern_type="stix",
    pattern_version="2.1",
    external_references=comsvcs_references,
    object_marking_refs=[stix2.TLP_WHITE]
)


## Indicators
indicator__comsvcs_p0001 = stix2.Indicator(
    id="indicator--" + str(uuid.uuid5(delta_namespace, "comsvcs_p0001")),
    created_by_ref=d2s.delta_identity,
    name="Comsvcs.dll Created Dump File of Process with MiniDump",
    pattern="[process:command_line MATCHES 'comsvcs'] AND [process:command_line MATCHES 'MiniDump']",
    pattern_type="stix",
    pattern_version="2.1",
    valid_from="2018-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE]
)

delta__comsvcs_p0002 = Delta(
    delta="comsvcs_p0002",
    delta_category="single-line-match",
    delta_meta=[],
    id=_delta + str(uuid.uuid5(delta_namespace, "comsvcs_p0002")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Comsvcs.dll Called MiniDumpW Function to Dump Process",
    description="Comsvcs.dll Created Dump File with MiniDumpW (#24) Function of a Process",
    pattern="[process:command_line MATCHES 'comsvcs'] AND ([process:command_line MATCHES '#24'] OR [process:command_line MATCHES '-24'])",
    pattern_type="stix",
    pattern_version="2.1",
    external_references=comsvcs_references,
    object_marking_refs=[stix2.TLP_WHITE]
)

## Mitre Attack Pattern
attack_pattern__mitre_t1003 = map.attack_pattern_t1003001()


# SCO
## Data Import
sco_comsvcs_p0001_df = pd.read_csv(os.path.join(os.path.dirname(comsvcs_dir), "comsvcs_p0001.csv"))
sco_comsvcs_p0002_df = pd.read_csv(os.path.join(os.path.dirname(comsvcs_dir), "comsvcs_p0002.csv"))
sco_comsvcs_p0000_df = pd.read_csv(os.path.join(os.path.dirname(comsvcs_dir), "comsvcs_p0000.csv"))


## Common Var
sco_namespace = d2s.sco_namespace


# SCO Generation Functions
def sco_comsvcs_p0001():
    sco_list = []

    for index, row in sco_comsvcs_p0001_df.iterrows():
        sco_cmdline = row["command_line"]
        sco_json = stix2.Process(
            id="process--" + str(uuid.uuid5(delta_namespace, sco_cmdline)),
            command_line=sco_cmdline
        )

        sco_list.append(sco_json)

    return sco_list


def sco_comsvcs_p0002():
    sco_list = []

    for index, row in sco_comsvcs_p0002_df.iterrows():
        sco_cmdline = row["command_line"]
        sco_json = stix2.Process(
            id="process--" + str(uuid.uuid5(delta_namespace, sco_cmdline)),
            command_line=sco_cmdline
        )

        sco_list.append(sco_json)

    return sco_list


def sco_comsvcs_p0000():
    sco_list = []

    for index, row in sco_comsvcs_p0000_df.iterrows():
        sco_cmdline = row["command_line"]
        sco_json = stix2.Process(
            id="process--" + str(uuid.uuid5(delta_namespace, sco_cmdline)),
            command_line=sco_cmdline
        )

        sco_list.append(sco_json)

    return sco_list


# SRO
def sro_comsvcs():
    sro_list = []
    sco_comsvcs_p0001_list = sco_comsvcs_p0001()

    for item in sco_comsvcs_p0001_list:
        sco = stix2.Relationship(source_ref=item.id, target_ref=indicator__comsvcs_p0001.id,
                                 relationship_type="indicates")
        sro_list.append(sco)

    sco_comsvcs_p0002_list = sco_comsvcs_p0002()

    for item in sco_comsvcs_p0002_list:
        sco = stix2.Relationship(source_ref=item.id, target_ref=indicator__comsvcs_p0002.id,
                                 relationship_type="indicates")
        sro_list.append(sco)

    sro1 = stix2.Relationship(source_ref=indicator__comsvcs_p0001, target_ref=delta__comsvcs_p0001, relationship_type="indicates")
    sro2 = stix2.Relationship(source_ref=indicator__comsvcs_p0002, target_ref=delta__comsvcs_p0002, relationship_type="indicates")
    sro3 = stix2.Relationship(source_ref=indicator__comsvcs_p0001, target_ref=delta__comsvcs_p0003, relationship_type="indicates")
    sro4 = stix2.Relationship(source_ref=indicator__comsvcs_p0002, target_ref=delta__comsvcs_p0003, relationship_type="indicates")
    sro5 = stix2.Relationship(source_ref=indicator__comsvcs_p0001, target_ref=attack_pattern__mitre_t1003['id'], relationship_type="indicates")
    sro6 = stix2.Relationship(source_ref=indicator__comsvcs_p0002, target_ref=attack_pattern__mitre_t1003['id'], relationship_type="indicates")
    sro7 = stix2.Relationship(source_ref=delta__comsvcs_p0001, target_ref=attack_pattern__mitre_t1003['id'], relationship_type="relates-to")
    sro8 = stix2.Relationship(source_ref=delta__comsvcs_p0002, target_ref=attack_pattern__mitre_t1003['id'], relationship_type="relates-to")
    sro9 = stix2.Relationship(source_ref=delta__comsvcs_p0003, target_ref=attack_pattern__mitre_t1003['id'], relationship_type="relates-to")

    sro_list.extend([sro1, sro2, sro3, sro4, sro5, sro6, sro7, sro8, sro9])


    return sro_list


# SBO
def bundle__comsvcs_p0000():

    bundle = stix2.Bundle(
        objects=[
            delta__comsvcs_p0001, delta__comsvcs_p0002, delta__comsvcs_p0003,
            indicator__comsvcs_p0001, indicator__comsvcs_p0002, attack_pattern__mitre_t1003
        ],
        allow_custom=True,
        id='bundle--' + str(uuid.uuid5(delta_namespace, 'comsvcs_p0000'))
    )

    sco_comsvcs_p0001_list = sco_comsvcs_p0001()

    for item in sco_comsvcs_p0001_list:
        bundle.objects.append(item)

    sco_comsvcs_p0002_list = sco_comsvcs_p0002()

    for item in sco_comsvcs_p0002_list:
        bundle.objects.append(item)

    sro_list = sro_comsvcs()

    for item in sro_list:
        bundle.objects.append(item)

    return bundle


