import delta2.stix as d2s
import uuid
import stix2


# Common Variables
_shared_references = [
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


comsvcs__p0001___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "comsvcs-p0001--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Comsvcs.dll Called MiniDump or MiniDumpW on Command Line",
    description="Pattern Representing Evidence of Comsvcs Being Used for Process Memory Dumping",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_references,
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


comsvcs__p0002___process_create__windows_any__mde = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "comsvcs-p0002--process_create-windows_any__mde")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Comsvcs.dll Used to Create a Dump File",
    description="Pattern Representing Evidence of Comsvcs Being Used for Process Memory Dumping",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_references,
    labels=[],
    x_delta_pid="comsvcs-p0002--process_create-windows_any-mde",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[file_name ENDSWITH '.dmp'] AND [initiating_process_command_line contains 'comsvcs']",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "procedure": "process_memory_dumping"
    }
)


comsvcs__p0003___read_process_memory__windows_any__mde = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "comsvcs-p0003--read_process_memory-windows_any__mde")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Comsvcs Accessed LSASS via Rundll in ReadProcessApiCall Data and Dumped Memory",
    description="Pattern Representing Evidence of Comsvcs Being Used for Process Memory Dumping",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_references,
    labels=[],
    x_delta_pid="comsvcs-p0003--read_process_memory-windows_any-mde",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[file_name IS lsass.exe] AND [initiating_process_command_line contains 'comsvcs'] AND [initiating_process_command_line contains 'minidump' OR 'minidumpw' OR '#24' OR '-24']",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "procedure": "process_memory_dumping"
    }
)

