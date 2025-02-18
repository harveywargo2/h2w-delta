

def adfind_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('objectcategory', 'organizationalUnit', '-f')
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Adfind Enumeration Filter ObjectCategory by OU",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def adfind_p0002(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has 'trustdmp'
            and ProcessCommandLine has_any ('-gcb', '-sc', '-gc')
        """
    query_json = {
        "delta": ["adfind-p0002--process_create-windows_any"],
        "title": "Adfind Enumeration Via Trustdmp Command",
        "mitre_technique": "t1482",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json

