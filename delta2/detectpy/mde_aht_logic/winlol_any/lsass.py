

def lsass_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('Get', 'Process' , 'lsass')
            and ProcessCommandLine contains 'Get-Process'
        """
    query_json = {
        "delta": ["lsass-p0001--process_create-windows_any"],
        "title": "Powershell Get-Process LSASS Command",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def lsass_p0002(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where FileName =~ 'lsass.exe'
            and AccountName !~ 'system'
        """
    query_json = {
        "delta": ["lsass-p0002--process_create-windows_any"],
        "title": "LSASS Execution From Non System Account",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def lsass_p0003(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and AccountName !~ 'system'
        """
    query_json = {
        "delta": ["lsass-p0003--read_process_memory-windows_any-mde"],
        "title": "LSASS Memory Read Non System Account",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def lsass_p0004(kql_ago='1d'):

    query_text = f"""DeviceFileEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'FileCreated'
            and FileName has_all ('lsass', 'dmp')
        """
    query_json = {
        "delta": ["lsass-p0004--file_create-windows_any"],
        "title": "LSASS DMP File Created",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def lsass_p0005(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('lsass', 'dmp')
            or ProcessCommandLine contains 'lsass.dmp'
        """
    query_json = {
        "delta": ["lsass-p0005--process_create-windows_any"],
        "title": "LSASS DMP File Created",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def lsass_p0006(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and parse_json(AdditionalFields).TotalBytesCopied > 20000000
    
        """
    query_json = {
        "delta": ["lsass-p0006--read_process_memory-windows_any-mde"],
        "title": "Large LSASS Memory Read",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def lsass_p0007(kql_ago='1d'):
    query_text = f"""DeviceEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessFileName has 'rundll'
            and parse_json(AdditionalFields).TotalBytesCopied >= 20000000
        """
    query_json = {
        "delta": ["lsass-p0007--read_process_memory-windows_any-mde"],
        "title": "Large LSASS Memory Read From Rundll",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
    }

    return query_json


def lsass_p0008(kql_ago='1d'):
    query_text = f"""DeviceEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessFileName =~ 'taskmgr.exe'
            and parse_json(AdditionalFields).TotalBytesCopied >= 20000000
        """
    query_json = {
        "delta": ["lsass-p0008--read_process_memory-windows_any-mde"],
        "title": "Large LSASS Memory Read From Taskmgr",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
    }

    return query_json