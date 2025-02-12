import delta2.stix as d2s
import uuid


process_create__windows_any = d2s.XDeltaData(
    id=d2s.x_delta_data + str(uuid.uuid5(d2s.delta_namespace, "process_create--windows_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Process Creation Data From Any Windows Device",
    external_references=[
        {
            "source_name": "Sysmon Community Guid",
            "url": "https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/process-creation.md"
        },
        {
            "source_name": "Windows Ultimate Security",
            "url": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001"
        },
        {
            "source_name": "DeviceProcessEvents",
            "url": "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table"
        }
    ],
    x_delta_data="process_create--windows_any",
    x_data_requirements={
        "fields": [
            "command_line",
            "file_name",
            "file_path",
            "initiating_command_line",
            "initiating_file_name",
            "initiating_file_path"
        ]
    },
    x_data_info={
        "collection_methods": [
            "sysmon",
            "mde"
        ]
    }
)

