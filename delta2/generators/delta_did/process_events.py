import delta2.stix as d2s
import uuid


process_create__windows_any = d2s.XDeltaDid(
    id=d2s.x_delta_did + str(uuid.uuid5(d2s.delta_namespace, "process_create--windows_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Process Creation Event From Any Windows OS",
    x_delta_did="process_create--windows_any",
    x_did_reqs={
        "file_name": "File name of the executable",
        "file_path": "Full path of the executable image that was executed",
        "process_command_line": "Command line used to create the new process or execute image",
        "initiating_process_file_name": "File path that spawned/created the main process",
        "initiating_process_command_line": "Command line used to run the process that initiated the event",
    },
    x_did_ns_obj={
        "collection_methods": [
            "sysmon",
            "mde"
        ]
    }
)

