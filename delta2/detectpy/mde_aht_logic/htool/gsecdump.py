

def gsecdump_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has 'gsecdump'
            or FileName has 'gsecdump'
        """
    query_json = {
        "delta": ["gsecdump-p0001--process_create-windows_any"],
        "title": "Gsecdump Indicator",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t1003.001", "t1003.002"],
        "query": query_text
        }

    return query_json

