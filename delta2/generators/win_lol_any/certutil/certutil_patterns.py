import delta2.stix as d2s
import uuid
import stix2


# Common Variables
_shared_references = [
    {
        "source_name": "atomic red team",
        "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-5---dump-volume-shadow-copy-hives-with-certutil"
    },
    {
"source_name": "atomic red team",
        "url": "https://lolbas-project.github.io/lolbas/Binaries/Certutil/"
    }
]


certutil__p0001___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "certutil-p0001--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Certutil Creating Volume Shadow Copy",
    description="Pattern Representing Evidence of Certutil IOC",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_references,
    labels=[],
    x_delta_pid="certutil-p0001--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'certutil' AND 'HardDiskVolumeShadowCopy']",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.002",
        "procedure": "copy_from_registry"
    }
)

