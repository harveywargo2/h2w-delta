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
    }
]

adfind__p0001___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "adfind-p0001--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Adfind Enumeration of Active Directory Organizational Units Via Filter ObjectCategory",
    description="Pattern Representing Evidence of Adfind AD Enumeration",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references="",
    labels=[],
    x_delta_pid="adfind-p0001--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'objectcategory' AND '-f' AND 'organizationalUnit']",
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
    name="Adfind Enumeration of Active Directory Domain Trusts Via Trustdmp Command",
    description="Pattern Representing Evidence of Adfind AD Enumeration",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references="",
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

