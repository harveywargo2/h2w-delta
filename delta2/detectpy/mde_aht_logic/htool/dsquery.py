def dsquery_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('dsquery', 'objectClass=trustedDomain')
        """
    query_json = {
        "delta": ["dsquery-p0001--process_create-windows_any"],
        "title": "Dsquery Trustdmp Command",
        "mitre_technique": "t1482",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json