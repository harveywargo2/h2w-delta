import delta2.stix as d2s
import uuid
import stix2


# Commone Var
_shared_references = [
    {
        "source_name": "JohnLaTxC",
        "url": "https://gist.github.com/JohnLaTwC/3e7dd4cd8520467df179e93fb44a434e"
    },
    {
        "source_name": "LOLBAS",
        "url": "https://lolbas-project.github.io/lolbas/Binaries/Rundll32/"
    }
]



rundll__p0001___process_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "rundll-p0001--process_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Rundll Called MiniDump or MiniDumpW on Command Line",
    description="Pattern Representing Evidence of Rundll Being Used for Process Memory Dumping",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_references,
    labels=[],
    x_delta_pid="rundll-p0001--process_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[file_name IN ('rundll32.exe', 'rundll64.exe)] AND [process_command_line CONTAINS 'minidump' OR 'minidumpw' OR '#24' OR '-24']",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "procedure": "process_memory_dumping"
    }
)


rundll__p0002___file_create__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "rundll-p0002--file_create-windows_any")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Rundll Created a Dump File",
    description="Pattern Representing Evidence of Rundll Being Used for Process Memory Dumping",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_references,
    labels=[],
    x_delta_pid="rundll-p0002--file_create-windows_any",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[file_name ENDSWITH '.dmp'] AND [initiating_process_file_name IN ('rundll32.exe', 'rundll64.exe)]",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "procedure": "process_memory_dumping"
    }
)


rundll__p0003___read_process_memory__windows_any = d2s.XDeltaPid(
    id=d2s.x_delta_pid + str(uuid.uuid5(d2s.delta_namespace, "rundll-p0003--read_process_memory-windows_any-mde")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name=" Rundll Accessed LSASS Via ReadProcessApiCall Event and Dumped Memory",
    description="Pattern Representing Evidence of Rundll Being Used for Process Memory Dumping",
    object_marking_refs=[stix2.TLP_WHITE],
    external_references=_shared_references,
    labels=[],
    x_delta_pid="rundll-p0003--read_process_memory-windows_any-mde",
    x_delta_category="single_line_match",
    x_delta_info={
        "pattern_case": "insensitive",
        "pattern": "[file_name IS lsass.exe] AND [initiating_process_file_name in (('rundll32.exe', 'rundll64.exe)] AND [initiating_process_command_line contains 'minidump' OR 'minidumpw' OR '#24' OR '-24']",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "procedure": "process_memory_dumping"
    }
)