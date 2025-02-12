import uuid


# reserved UUID for generating UUIDv5s
delta_namespace = uuid.UUID("d0d00000-28f6-485e-851e-e52ba07a2091")
sco_namespace = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


# identity = identity--6c7d8a77-1bf5-5fd4-a66d-02d9955117d9
delta_identity = "identity--" + str(uuid.uuid5(delta_namespace, 'h2w-delta'))


# Schema Base
schema_base = "https://raw.githubusercontent.com/harveywargo2/h2w-delta/refs/heads/main/schemas/"


# Common Variables
default_timestamp = "2018-01-01T00:00:00.000Z"


# Delta Objects Strings
x_delta_data = 'x-delta-data--'


# x-delta-tier template
# tier0-threat000-detect000-alert000
delta_con_calibration_template = [
    {
        "tier": 0,
        "threat_presence": 0,
        "threat_capability_gain": 0,
        "threat_reported_usage": 0,
        "detect_resource_utilization": 0,
        "detect_maintenance": 0,
        "detect_bypass": 0,
        "alert_projection": 0,
        "alert_urgency": 0,
        "alert_triage_effort": 0
    }
]