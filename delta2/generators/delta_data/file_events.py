import delta2.stix as d2s
import uuid


file_create___windows_any = d2s.XDeltaData(
    id=d2s.x_delta_data + str(uuid.uuid5(d2s.delta_namespace, "file_create--windows_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="File Creation Event From Any Windows Device",
    external_references=[
        {
            "source_name": "Sysmon Community Guid",
            "url": "https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/file-create.md"
        },
        {
            "source_name": "Windows Ultimate Security",
            "url": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001"
        },
        {
            "source_name": "MDE Advanced Hunting Table",
            "url": "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table"
        }
    ],
    x_delta_data="file_create--windows_any",
    x_data_requirements={
        "fields": [
            "file_name",
            "file_path"
        ]
    },
    x_data_info={
        "collection_methods": [
            "sysmon",
            "mde"
        ]
    }
)

file_create__mde___windows_any = d2s.XDeltaData(
    id=d2s.x_delta_data + str(uuid.uuid5(d2s.delta_namespace, "file_create-mde--windows_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="File Creation Event From MDE From Any Windows Device",
    external_references=[
        {
            "source_name": "MDE Advanced Hunting Table",
            "url": "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table"
        }
    ],
    x_delta_data="file_create_mde--windows_any",
    x_data_requirements={
        "fields": [
            "file_name",
            "file_path",
            "initiating_process_command_line"
        ]
    },
    x_data_info={
        "collection_methods": ["mde"]
    }
)