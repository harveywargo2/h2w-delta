

def rundll_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where FileName in~ ('rundll32.exe', 'rundll64.exe')
            and ProcessCommandLine has_any ('minidump', 'minidumpw', '#24', '-24')
        | where ProcessCommandLine contains ' minidump '
            or ProcessCommandLine contains ' minidump '
            or ProcessCommandLine contains ' #24 '
            or ProcessCommandLine contains ' -24 '
        """
    query_json = {
        "delta": ["rundll-p0001--process_create-windows_any"],
        "title": "Rundll Called MiniDump On Command Line",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def rundll_p0002(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessFileName in~ ('rundll32.exe', 'rundll64.exe')
            and InitiatingProcessCommandLine has_any ('minidump', 'minidumpw', '#24', '-24')
        | where InitiatingProcessCommandLine contains ' -24 '
            or InitiatingProcessCommandLine contains ' #24 '
            or InitiatingProcessCommandLine contains ' minidump '
            or InitiatingProcessCommandLine contains ' minidumpw '
        """
    query_json = {
        "delta": ["rundll-p0002--read_process_memory-windows_any-mde"],
        "title": "Rundll Created MiniDump of LSASS Process Memory",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json

