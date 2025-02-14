import delta2.stix as d2s
import uuid
import stix2
from delta2.stix import x_delta_evidence
import comsvcs_common




# comsvcs-p0001--process_create-windows_any
comsvcs__p0001___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "comsvcs-p0001--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Comsvcs.dll Called MiniDump on Command Line",
    description="Comsvcs.dll lolbin used to create artifact of process dumping with MiniDump on Process Command Line.",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=comsvcs_common._shared_references,
    labels=[],
    x_delta_pid="comsvcs-p0001--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "stix_pattern": "[process:command_line MATCHES 'comsvcs'] AND [process:command_line MATCHES 'minidump']",
        "delta_data": ["process_create-windows_any"],
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001"
    }
)


comsvcs__p0001___delta_evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "comsvcs-p0002--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Evidence Container for delta comsvcs-p0001",
    x_delta_evidence="comsvcs-p0001--evidence",
    x_evidence_info=[
        {
            "type": "reference",
            "source": "JohnLaTwC GIST",
            "url": "https://gist.github.com/JohnLaTwC/3e7dd4cd8520467df179e93fb44a434e",
            "date": "2021-06-23",
            "pattern_count": 4,
            "patterns": comsvcs_common._p0001_evidence_list
        }
    ]
)