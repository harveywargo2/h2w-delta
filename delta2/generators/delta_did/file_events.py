import delta2.stix as d2s
import uuid


file_create__windows_any = d2s.XDeltaDid(
    id=d2s.x_delta_did + str(uuid.uuid5(d2s.delta_namespace, "file_create-windows_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="File Creation Event From Any Windows OS",
    x_delta_did="file_create--windows_any",
    x_did_reqs={
        "file_name": "File name of file created",
        "file_path": "Folder path of file created",
        "initiating_process_file_name": "Initiating process file name that created the file"
    },
    x_did_ns_obj={
        "collection_methods": ["sysmon", "mde via msft agent"]
    }
)


file_create_mde__windows_any = d2s.XDeltaDid(
    id=d2s.x_delta_did + str(uuid.uuid5(d2s.delta_namespace, "file_create_mde-windows_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="MDE File Creation Event From Any Windows OS",
    x_delta_did="file_create_mde-windows_any",
    x_did_reqs={
        "file_name": "File name of file created",
        "file_path": "Folder path of file created",
        "initiating_process_file_name": "Process file name that created the file",
        "initiating_process_command_line": "Command line that created the file",
    },
    x_did_ns_obj={
        "collection_methods": ["mde via msft agent"]
    }
)