import delta2.stix as d2s
import uuid
import stix2


_adfind_p0001_e01 = {
    "evidence_type": "emulation",
    "evidence_source": "atomic_red_team",
    "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md#atomic-test-4---adfind---enumerate-active-directory-ous",
    "ns_meta": {
        "guid": "d1c73b96-ab87-4031-bad8-0e1b3b8bf3ec",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''"path\AdFind.exe -f (objectcategory=organizationalUnit)"'''}
}


_adfind_p0001_e02 = {
    "evidence_type": "intel_report",
    "evidence_source": "dfir",
    "url": "https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/",
    "ns_meta": {
        "date": "2022-08-08",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {
        "process_command_line": r'''adFind.exe -f "(objectcategory=organizationalUnit)" > ad_ous.txt'''
    }
}


adfind__p0001___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0001--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container adfind-p0001",
    x_delta_evidence="adfind-p0001--evidence",
    x_evidence_info=[_adfind_p0001_e01, _adfind_p0001_e02]
)


_adfind_p0002_e01 = {
    "evidence_type": "emulation",
    "evidence_source": "atomic_red_team",
    "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md#atomic-test-5---adfind---enumerate-active-directory-trusts",
    "ns_meta": {
        "guid": "15fe436d-e771-4ff3-b655-2dca9ba52834",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''path\AdFind.exe -gcb -sc trustdmp'''}
}


_adfind_p0002_e02 = {
    "evidence_type": "intel_report",
    "evidence_source": "dfir",
    "url": "https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/",
    "ns_meta": {
        "date": "2022-08-08",
    },
    "pattern_type": "dict_list",
    "pattern_count": 2,
    "patterns": [
        {
            "process_command_line": r'''af.exe -sc trustdmp > trustdmp.txt'''
        },
        {
            "process_command_line": r'''adfind.exe -sc trustdmp > trustdmp.txt'''
        }
    ]
}


_adfind_p0002_e03 = {
    "evidence_type": "intel_report",
    "evidence_source": "dfir",
    "url": "https://thedfirreport.com/2020/05/08/adfind-recon/",
    "ns_meta": {
        "date": "2020-05-08",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''adfind.exe -gcb -sc trustdmp > trustdmp.txt'''}
}


adfind__p0002___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0002--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container adfind-p0002",
    x_delta_evidence="adfind-p0002--evidence",
    x_evidence_info=[_adfind_p0002_e01, _adfind_p0002_e02, _adfind_p0002_e03]
)


_adfind_p0003_e01 = {
    "evidence_type": "intel_report",
    "evidence_source": "dfir",
    "url": "https://thedfirreport.com/2020/05/08/adfind-recon/",
    "ns_meta": {
        "date": "2020-05-08",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''adfind.exe -sc dclist > dclist.txt'''}
}


adfind__p0003___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0003--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container adfind-p0003",
    x_delta_evidence="adfind-p0003--evidence",
    x_evidence_info=[_adfind_p0003_e01]
)


_adfind_p0004_e01 = {
    "evidence_type": "intel_report",
    "evidence_source": "dfir",
    "url": "https://thedfirreport.com/2020/05/08/adfind-recon/",
    "ns_meta": {
        "date": "2020-05-08",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''adfind.exe -sc domainlist > domainlist.txt'''}
}


adfind__p0004___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0004--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container adfind-p0004",
    x_delta_evidence="adfind-p0004--evidence",
    x_evidence_info=[_adfind_p0004_e01]
)


_adfind_p0005_e01 = {
    "evidence_type": "intel_report",
    "evidence_source": "dfir",
    "url": "https://thedfirreport.com/2020/05/08/adfind-recon/",
    "ns_meta": {
        "date": "2020-05-08",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''adfind.exe -sc computers_pwdnotreqs > computers_pwdnotreqd.txt'''}
}


adfind__p0005___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0005--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container adfind-p0005",
    x_delta_evidence="adfind-p0005--evidence",
    x_evidence_info=[_adfind_p0005_e01]
)


_adfind_p0006_e01 = {
    "evidence_type": "intel_report",
    "evidence_source": "dfir",
    "url": "https://thedfirreport.com/2020/05/08/adfind-recon/",
    "ns_meta": {
        "date": "2020-05-08",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''adfind.exe -f "objectcategory=computer" > ad_computers.txt'''}
}


_adfind_p0006_e02 = {
    "evidence_type": "intel_report",
    "evidence_source": "dfir",
    "url": "https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/",
    "ns_meta": {
        "date": "2022-08-08",
    },
    "pattern_type": "dict_list",
    "pattern_count": 1,
    "patterns": [
        {
            "process_command_line": r'''adfind.exe -f "objectcategory=computer" > ad_computers.txt'''
        },
        {
            "process_command_line": r'''af.exe -f "objectcategory=computer" > ad_computers.txt'''
        }
    ]
}


adfind__p0006___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0006--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container adfind-p0006",
    x_delta_evidence="adfind-p0006--evidence",
    x_evidence_info=[_adfind_p0006_e01, _adfind_p0006_e02]
)


_adfind_p0007_e01 = {
    "evidence_type": "intel_report",
    "evidence_source": "dfir",
    "url": "https://thedfirreport.com/2020/05/08/adfind-recon/",
    "ns_meta": {
        "date": "2020-05-08",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''adfind.exe -f "objectcategory=person" > ad_users.txt'''}
}


_adfind_p0007_e02 = {
    "evidence_type": "intel_report",
    "evidence_source": "dfir",
    "url": "https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/",
    "ns_meta": {
        "date": "2022-08-08",
    },
    "pattern_type": "dict_list",
    "pattern_count": 1,
    "patterns": [
        {
            "process_command_line": r'''adfind.exe -f "objectcategory=person" > ad_users.txt'''
        },
        {
            "process_command_line": r'''af.exe -f "objectcategory=person" > ad_users.txt'''
        }
    ]
}


adfind__p0007___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0007--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container adfind-p0007",
    x_delta_evidence="adfind-p0007--evidence",
    x_evidence_info=[_adfind_p0007_e01, _adfind_p0007_e02]
)

