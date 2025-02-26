

def comsvcs_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('comsvcs', 'minidump')
            and ProcessCommandLine has_any ('#24', '-24', 'minidump', 'minidumpw', '24')
        """
    query_json = {
        "delta": "comsvcs-p0001--process_create-windows_any",
        "title": "Comsvcs.dll Called MiniDump on Command Line",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def comsvcs_p0002(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has 'comsvcs'
            and ProcessCommandLine has_any ('#24', '-24', 'minidumpw')
        """
    query_json = {
        "delta": "comsvcs-p0002--process_create-windows_any",
        "title": "Comsvcs.dll Called MiniDumpW on Command Line",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def comsvcs_p0003(kql_ago='1d'):

    query_text = f"""DeviceFileEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'FileCreated'
            and InitiatingProcessCommandLine has 'comsvcs'
            and FileName endswith '.dmp'
        """
    query_json = {
        "delta": "comsvcs-p0003--file_create-windows_any",
        "title": "Comsvcs.dll Used to Create a Dump File",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }
    return query_json


def comsvcs_p0004(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessCommandLine has 'comsvcs'
        | where InitiatingProcessCommandLine has_any ('#24', '-24', '24', 'minidump', 'minidumpw')
        """
    query_json = {
        "delta": "comsvcs-p0004--read_process_memory-windows_any-mde",
        "title": "Comsvcs.dll Read LSASS Via Rundll to Create Memory Dump of LSASS",
        "query": query_text
        }

    return query_json

