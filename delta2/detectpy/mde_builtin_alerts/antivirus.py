

def msftav_p0001(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
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


def msftav_p0002(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'adfind'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'adfind'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Adfind MDE Av Detection",
        "mitre_technique": ["t1482"],
        "mitre_sub_technique": "t10003.001",
        "query": query_text
        }

    return query_json


def msftav_p0003(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'gsecdump'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'gsecdump'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "Gsecdump MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001", "t1003.002"],
        "query": query_text
        }

    return query_json


def msftav_p0004(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'presenoker'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'presenoker'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "presenoker MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001", "t1003.002"],
        "query": query_text
        }

    return query_json


def msftav_p0005(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'ATPMiniDump'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'ATPMiniDump'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "ATPMiniDump MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001"],
        "query": query_text
        }

    return query_json


def msftav_p0006(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'DumpLsass'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'DumpLsass'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "DumpLsass MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001"],
        "query": query_text
        }

    return query_json


def msftav_p0007(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'Posdercan'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'Posdercan'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "Posdercan MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.002"],
        "query": query_text
        }

    return query_json


def msftav_p0008(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'RegistryExfil'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'RegistryExfil'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "RegistryExfil MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.002"],
        "query": query_text
        }

    return query_json


def msftav_p0009(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'Mimikatz'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'Mimikatz'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "Mimikatz MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.002"],
        "query": query_text
        }

    return query_json


def msftav_p0010(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'Powersploit'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'Powersploit'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "Powersploit MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001"],
        "query": query_text
        }

    return query_json

