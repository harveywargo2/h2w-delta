import delta2.stix as d2s
import uuid
import stix2


_shared_reference = [
    {
        "source_name": "DFIR",
        "url": "https://thedfirreport.com/2020/05/08/adfind-recon/"
    },
    {
        "source_name": "JoeWare",
        "url": "https://www.joeware.net/freetools/tools/adfind/usage.htm"
    },
    {
        "source_name": "DFIR",
        "url": "https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/"
    }
]

adfind__p0001___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0001--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Adfind Enumeration of Active Directory By ObjectCategory Filter By OU Command",
    description="Pattern Representing Evidence of Adfind AD Enumeration",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_reference,
    labels=[],
    x_delta_pid="adfind-p0001--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'objectcategory=organizationalUnit' AND '-f']",
        "mitre_technique": "t1482",
        "mitre_sub_technique": "",
        "procedure": "ad_enumeration"
    }
)


adfind__p0002___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0002--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Adfind Enumeration of Active Directory By Trustdmp Command",
    description="Pattern Representing Evidence of Adfind AD Enumeration",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_reference,
    labels=[],
    x_delta_pid="adfind-p0002--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'trustdmp'] AND [process_command_line CONTAINS '-gcb' OR '-sc' OR '-gc']",
        "mitre_technique": "t1482",
        "mitre_sub_technique": "",
        "procedure": "ad_enumeration"
    }
)


adfind__p0003___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0003--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Adfind Enumeration of Active Directory By Dclist Command",
    description="Pattern Representing Evidence of Adfind AD Enumeration",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_reference,
    labels=[],
    x_delta_pid="adfind-p0003--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'dclist'] AND [process_command_line CONTAINS '-gcb' OR '-sc' OR '-gc']",
        "mitre_technique": "t1018",
        "mitre_sub_technique": "",
        "procedure": "ad_enumeration"
    }
)


adfind__p0004___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0004--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Adfind Enumeration of Active Directory By DomainList Command",
    description="Pattern Representing Evidence of Adfind AD Enumeration",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_reference,
    labels=[],
    x_delta_pid="adfind-p0004--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'domainlist'] AND [process_command_line CONTAINS '-gcb' OR '-sc' OR '-gc']",
        "mitre_technique": "",
        "mitre_sub_technique": "",
        "procedure": "ad_enumeration"
    }
)


adfind__p0005___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0005--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Adfind Enumeration of Active Directory By PwdNotReqD Command",
    description="Pattern Representing Evidence of Adfind AD Enumeration",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_reference,
    labels=[],
    x_delta_pid="adfind-p0005--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'users_pwdnotreqd' OR 'computers_pwdnotreqd'] AND [process_command_line CONTAINS '-gcb' OR '-sc' OR '-gc']",
        "mitre_technique": "",
        "mitre_sub_technique": "",
        "procedure": "ad_enumeration"
    }
)


adfind__p0006___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0006--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Adfind Enumeration of Active Directory By ObjectCat Filter on Computers Command",
    description="Pattern Representing Evidence of Adfind AD Enumeration",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_reference,
    labels=[],
    x_delta_pid="adfind-p0006--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'objectcategory=computer' AND '-f']",
        "mitre_technique": "t1018",
        "mitre_sub_technique": "",
        "procedure": "ad_enumeration"
    }
)


adfind__p0007___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0007--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Adfind Enumeration of Active Directory By ObjectCat Filter on Person Command",
    description="Pattern Representing Evidence of Adfind AD Enumeration",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_reference,
    labels=[],
    x_delta_pid="adfind-p0007--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'objectcategory=person' AND '-f']",
        "mitre_technique": "t1087.002",
        "mitre_sub_technique": "",
        "procedure": "ad_enumeration"
    }
)


adfind__p0008___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0008--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Adfind Enumeration Command Redirected To File",
    description="Pattern Representing Evidence of Adfind AD Enumeration",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_reference,
    labels=[],
    x_delta_pid="adfind-p0008--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'objectcategory=person' OR 'objectcategory=computer' OR 'objectcategory=subnet' OR 'objectcategory=organizationalUnit' OR 'domainlist' OR 'trustdmp' OR 'adinfo' OR 'dclist'] AND [process_command_line CONTAINS '-f' OR '-sc-] AND [process_command_line CONTAINS ' > ' OR ' >> ']",
        "mitre_technique": ["t1482", "t1087.002", "t1018"],
        "mitre_sub_technique": "",
        "procedure": "ad_enumeration"
    }
)