from delta2.common import (x_delta_did, delta_namespace, delta_identity)
import delta2.stix as d2s
import uuid


read_process_memory__windows_any = d2s.XDeltaDid(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, "read_process_memory_mde-windows_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="MDE Read Process Memory From Any Windows OS",
    x_delta_did="read_process_memory--windows_any",
    x_did_reqs={
        "file_name": "File name that had process memory read",
        "file_path": "Folder path of file name",
    },
    x_did_ns_obj={
        "collection_methods": [
            "Threat Intelligence ETW Provider",
            "mde"
        ]
    }
)