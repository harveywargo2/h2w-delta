import delta2.stix as d2s
import uuid
import stix2


_certutil_p0001_e01 = {
    "evidence_type": "emulation",
    "evidence_source": "atomic_red_team",
    "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-5---dump-volume-shadow-copy-hives-with-certutil",
    "ns_meta": {
        "guid": "eeb9751a-d598-42d3-b11c-c122d9c3f6c7",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {
            "process_command_line": r'''certutil  -f -v -encodehex "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM" C:\Users\<uname>\AppData\Local\Temp\<filename> '''
        }

}


certutil__p0001___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "certutil-p0001--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container certutil-p0001",
    x_delta_evidence="certutil-p0001--evidence",
    x_evidence_info=[_certutil_p0001_e01]
)