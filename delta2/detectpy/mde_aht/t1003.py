

def t1003_pshell_get_lsass(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('Get', 'Process' , 'lsass')
            and ProcessCommandLine contains 'Get-Process'
        """
    query_json = {
        "delta": ["lsass-pid0001"],
        "title": "Powershell Get-Process LSASS Command",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json