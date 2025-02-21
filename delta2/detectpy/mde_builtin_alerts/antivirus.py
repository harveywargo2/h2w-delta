def msftav_p0001(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and Title contains 'rundlllolbin'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'rundlllolbin'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": ["comsvcs-p0001--process_create-windows_any"],
        "title": "RundllLolBin MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": "t10003.001",
        "query": query_text
        }

    return query_json

