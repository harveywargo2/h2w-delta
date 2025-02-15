

def rundll_minidump_on_cmdline(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where FileName in~ ('rundll32.exe', 'rundll64.exe')
            and ProcessCommandLine contains 'minidump'
        """
    query_json = {
        "delta": ["rundll-p0001--process_create--windows_any"],
        "title": "Rundll Called MiniDump On Command Line",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def rundll_minidumpw_function_on_cmdline(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where FileName in~ ('rundll32.exe', 'rundll64.exe')
            and ProcessCommandLine has_any ('-24', '#24')
        | where ProcessCommandLine contains ' -24 '
            or ProcessCommandLine contains ' #24 '
        """
    query_json = {
        "delta": ["rundll-p0002--process_create-windows_any"],
        "title": "Rundll Called MiniDumpW Function On CommandLine",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json