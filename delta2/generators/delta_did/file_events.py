from delta2.common import (x_delta_did, delta_namespace, delta_identity)
import delta2.stix as d2s
import uuid


_fc_any = "file_create-any"
_fe_mde_any = "file_event-any"

file_create__any = d2s.XDeltaDataId(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, _fc_any)),
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="File Creation Event From Any OS",
    description="File creation event from any OS collected by any method.",
    x_delta_data_id=_fc_any,
    x_data_reqs={
        "file_path": "Folder path of file created",
        "initiating_file_path": "Folder path of the file that created the file"
    },
    x_data_meta={
        "collection_methods": ["sysmon", "mde", "edr"],
        "operating_system": ["linux", "windows", "macos"]
    }
)


file_event_mde__any = d2s.XDeltaDataId(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, _fe_mde_any)),
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="MDE File Creation Event From Any Windows OS",
    description="File event from any OS collected by MSFT Defender Endpoint.",
    x_delta_data_id=_fe_mde_any,
    x_data_reqs={
        "file_action": "Type of file event recorded like FileCreated, FileRenamed, FileModified, FileDeleted",
        "file_name": "File name of file created",
        "file_path": "Folder path of file created",
        "sha256": "Sha256 of file",
        "md5": "MD5 of file",
        "sha1": "Sha1 of file",
        "initiating_process_file_name": "File name that created the file",
        "initiating_file_path": "Folder path of the file that created the file",
        "initiating_process_cmdline": "Command line that created the file",
        "initiating_process_account": "Account that created the file",
    },
    x_data_meta={
        "collection_methods": ["mde"],
        "operating_system": ["linux", "windows", "macos"]
    }
)