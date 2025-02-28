

def certutil_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('certutil', 'globalroot')
        """
    query_json = {
        "delta": ["certutil-p0001--process_create-windows_any"],
        "title": "Certutil Creating Volume Shadow Copy",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.002",
        "query": query_text
        }

    return query_json

