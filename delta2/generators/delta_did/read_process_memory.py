import delta2.stix as d2s
import uuid


read_process_memory__windows_any = d2s.XDeltaDid(
    id=d2s.x_delta_data + str(uuid.uuid5(d2s.delta_namespace, "read_process_memory_mde--windows_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="MDE Read Process Memory From Any Windows OS",
    x_delta_did="read_process_memory--windows_any",
    x_did_reqs={
    },
    x_did_ns_obj={
        "collection_methods": [
            "Threat Intelligence ETW Provider",
            "mde"
        ]
    }
)