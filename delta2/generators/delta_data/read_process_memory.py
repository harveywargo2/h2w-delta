import delta2.stix as d2s
import uuid


read_process_memory___windows_any = d2s.XDeltaData(
    id=d2s.x_delta_data + str(uuid.uuid5(d2s.delta_namespace, "read_process_memory--windows_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Read Process Memory From Any Windows Device",
    external_references=[
        {
            "source_name": "MSFT Threat Intelligence ETW Provider",
            "url": "https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-17134/Microsoft-Windows-Threat-Intelligence.xml"
        },
        {
            "source_name": "Window Doc",
            "url": "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory"
        },
        {
            "source_name": "MDE Advanced Hunting Table",
            "url": "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table"
        },
        {
            "source_name": "Elastic Security",
            "url": "https://www.elastic.co/security-labs/kernel-etw-best-etw"
        },
        {
            "source_name": "Undev Ninja",
            "url": "https://undev.ninja/introduction-to-threat-intelligence-etw/"
        }
    ],
    x_delta_data="read_process_memory--windows_any",
    x_data_requirements={
        "fields": []
    },
    x_data_info={
        "collection_methods": [
            "Threat Intelligence ETW Provider",
            "mde"
        ]
    }
)