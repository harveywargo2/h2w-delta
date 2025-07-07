from delta2.common import (x_delta_did, delta_namespace, delta_identity)
import delta2.stix as d2s
import uuid


# Common Var
_pc_any = "process_create-any"
_pc_win_any = "process_create-windows_any"
_pc_nix_any = "process_create-linux_any"
_pc_mac_any = "process_create-mac_any"
_pc_mde_any = "process_create_mde-any"


process_create__any = d2s.XDeltaDataId(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, _pc_any)),
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Process Creation Event From Any OS",
    description="Process creation event from any OS collected by any method.",
    x_delta_data_id=_pc_any,
    x_data_reqs={
        "process_cmdline": "Command line used to create the new process or execute image",
        "process_path": "Directory path of process",
        "account": "account associated with process",
        "initiating_process_cmdline": "Command line used to run the process that initiated the event",
        "initiating_process_path": "Directory path of initiating process"
    },
    x_data_meta={
        "collection_methods": ["sysmon", "mde", "edr"],
        "operating_system": ["linux", "windows", "macos"]
    }
)


process_create__windows_any = d2s.XDeltaDataId(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, _pc_win_any)),
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Process Creation Event From Any Windows OS",
    description="Process creation event from any Windows OS collected by any method.",
    x_delta_data_id=_pc_win_any,
    x_data_reqs={
        "process_cmdline": "Command line used to create the new process or execute image",
        "process_path": "Directory path of process",
        "account": "account associated with process",
        "initiating_process_cmdline": "Command line used to run the process that initiated the event",
        "initiating_process_path": "Directory path of initiating process",
        "original_process_name": "Original process name Windows only feature from PE"
    },
    x_data_meta={
        "collection_methods": ["sysmon", "mde", "edr"],
        "operating_system": ["windows"]
    }
)


process_create__linux_any = d2s.XDeltaDataId(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, _pc_nix_any)),
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Process Creation Event From Any Linux OS",
    description="Process creation event from any Linux OS collected by any method.",
    x_delta_did=_pc_nix_any,
    x_did_reqs={
        "process_cmdline": "Command line used to create the new process or execute image",
        "process_path": "Directory path of process",
        "account": "account associated with process",
        "initiating_process_cmdline": "Command line used to run the process that initiated the event",
        "initiating_process_path": "Directory path of initiating process"
    },
    x_did_ns_obj={
        "collection_methods": ["sysmon", "mde", "edr"],
        "operating_system": ["linux"]
    }
)


process_create__mac_any = d2s.XDeltaDataId(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, _pc_mac_any)),
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="Process Creation Event From Any Mac OS",
    description="Process creation event from any Mac OS collected by any method.",
    x_delta_did=_pc_mac_any,
    x_did_reqs={
        "process_cmdline": "Command line used to create the new process or execute image",
        "process_path": "Directory path of process",
        "account": "account associated with process",
        "initiating_process_cmdline": "Command line used to run the process that initiated the event",
        "initiating_process_path": "Directory path of initiating process"
    },
    x_did_ns_obj={
        "collection_methods": ["mde", "edr"],
        "operating_system": ["mac"]
    }
)


process_create_mde__any = d2s.XDeltaDataId(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, _pc_mde_any)),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Process Creation Event From MSFT Defender Endpoint From Any OS",
    x_delta_did=_pc_mde_any,
    x_did_reqs={
        "process_cmdline": "Command line used to create the new process or execute image",
        "process_path": "Directory path of process",
        "account": "account associated with process",
        "initiating_process_cmdline": "Command line used to run the process that initiated the event",
        "initiating_process_path": "Directory path of initiating process",
        "initiating_process_account": "Account name that ran the initiating process",
        "parent_initiating_process_cmdline": "Command line used to run the  parent process to the initiating process",
        "parent_initiating_process_path": "Directory path of parent process"
    },
    x_did_ns_obj={
        "collection_methods": ["mde"],
        "operating_system": ["windows", "linux", "macos"]
    }
)

