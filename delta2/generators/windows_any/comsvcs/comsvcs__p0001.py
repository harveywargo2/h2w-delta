import delta2.stix as d2s
import uuid
import stix2
import delta2.generators.windows_any.comsvcs.comsvcs_common as common


# comsvcs-p0001--process_create-windows_any
comsvcs__p0001___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "comsvcs-p0001--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Comsvcs.dll Called MiniDump or MiniDumpW on Command Line",
    description="Pattern Representing Evidence of Comsvcs Being Used for Process Memory Dumping",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=common._shared_references,
    labels=[],
    x_delta_pid="comsvcs-p0001--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[process_command_line CONTAINS 'comsvcs'] AND [process_command_line CONTAINS 'minidump' OR 'minidumpw' OR '#24' OR '-24']",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "procedure": "process_memory_dumping"
    }
)


comsvcs__p0001___delta_evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "comsvcs-p0001--evidence")),
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
            "pattern_count": 23,
            "patterns": common._p0001_evidence_list
        },
        {
            "type": "emulation",
            "source": "Atomic Red Team",
            "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-2---dump-lsassexe-memory-using-comsvcsdll",
            "date": "",
            "guid": "2536dee2-12fb-459a-8c37-971844fa73be",
            "pattern_count": 1,
            "patterns": [
                {
                    "initiating_process_command_line": r'''"C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full"'''
                }
            ]
        }
    ]
)

