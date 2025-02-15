

def comsvcs_process_dump_on_cmdline(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has 'comsvcs'
            and ProcessCommandLine has_any ('#24', '-24', 'minidump', 'minidumpw', '24')
        """
    query_json = {
        "delta": ["comsvcs-p0001--process_create-windows_any"],
        "title": "Comsvcs.dll Process Dump Indicator on Command Line",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def comsvcs_created_dmp_file(kql_ago='1d'):

    query_text = f"""DeviceFileEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'FileCreated'
            and InitiatingProcessCommandLine has 'comsvcs'
            and FileName endswith '.dmp'
        """
    query_json = {
        "delta": ["comsvcs-p0002--file_create-windows_any"],
        "title": "Comsvcs.dll Used to Create File",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }
    return query_json


def comsvcs_lsass_read_memory_dump(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessCommandLine has 'comsvcs'
        | where InitiatingProcessCommandLine has_any ('#24', '-24', '24', 'minidump', 'minidumpw')
        """
    query_json = {
        "delta": "",
        "title": "Comsvcs Accessed LSASS via Rundll in ReadProcessApiCall Data and Dumped Memory",
        "query": query_text
        }

    return query_json

