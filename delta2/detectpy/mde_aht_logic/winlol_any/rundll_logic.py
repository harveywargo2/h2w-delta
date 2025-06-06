

def rundll_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where FileName in~ ('rundll32.exe', 'rundll64.exe')
            and ProcessCommandLine has_any ('minidump')
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

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where FileName in~ ('rundll32.exe', 'rundll64.exe')
            and ProcessCommandLine has_any ('minidumpw', '#24', '-24')
        | where ProcessCommandLine contains ' minidump '
            or ProcessCommandLine contains ' #24 '
            or ProcessCommandLine contains ' -24 '
        """
    query_json = {
        "delta": ["rundll-p0001--process_create-windows_any"],
        "title": "Rundll Called MiniDumpW On Command Line",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def rundll_p0003(kql_ago='1d'):

    query_text = f"""DeviceFileEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'FileCreated'
            and InitiatingProcessFileName in~ ('rundll32.exe', 'rundll64.exe')
            and FileName endswith '.dmp'
        """
    query_json = {
        "delta": ["rundll-p0002--file_create-windows_any"],
        "title": "Rundll Created Dump File",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def rundll_p0004(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessFileName in~ ('rundll32.exe', 'rundll64.exe')
            and InitiatingProcessCommandLine has_any ('minidump', 'minidumpw', '#24', '-24')
        """
    query_json = {
        "delta": ["rundll-p0003--read_process_memory-windows_any-mde"],
        "title": "Rundll Created MiniDump of LSASS Process Memory",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json

