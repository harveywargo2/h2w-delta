from delta2.common import (x_delta_did, delta_namespace, delta_identity)
import delta2.stix as d2s
import uuid


process_create__any = d2s.XDeltaDid(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, "process_create-any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Process Creation Event From Any OS",
    x_delta_did="process_create-any",
    x_did_reqs={
        "process_cmdline": "Command line used to create the new process or execute image",
        "process_path": "Directory Path of Process",
        "account": "account associated with process",
        "initiating_process_cmdline": "Command line used to run the process that initiated the event",
        "initiating_process_path": "Directory Path of Initiating Process"
    },
    x_did_ns_obj={
        "collection_methods": ["sysmon", "mde"],
        "operating_system": ["linux", "windows"]
    }
)


process_create__windows_any = d2s.XDeltaDid(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, "process_create-windows_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Process Creation Event From Any Windows OS",
    x_delta_did="process_create-windows_any",
    x_did_reqs={
        "process_cmdline": "Command line used to create the new process or execute image",
        "process_path": "Directory Path of Process",
        "account": "account associated with process",
        "initiating_process_cmdline": "Command line used to run the process that initiated the event",
        "initiating_process_path": "Directory Path of Initiating Process"
    },
    x_did_ns_obj={
        "collection_methods": ["sysmon", "mde"],
        "operating_system": ["windows"]
    }
)


process_create__linux_any = d2s.XDeltaDid(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, "process_create-linux_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Process Creation Event From Any Linux OS",
    x_delta_did="process_create-windows_any",
    x_did_reqs={
        "process_cmdline": "Command line used to create the new process or execute image",
        "process_path": "Directory Path of Process",
        "account": "account associated with process",
        "initiating_process_cmdline": "Command line used to run the process that initiated the event",
        "initiating_process_path": "Directory Path of Initiating Process"
    },
    x_did_ns_obj={
        "collection_methods": ["sysmon", "mde"],
        "operating_system": ["linux"]
    }
)


process_create_mde__any = d2s.XDeltaDid(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, "process_create_mde-any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Process Creation Event From MSFT Defender Endpoint From Any OS",
    x_delta_did="process_create_mde-windows_any",
    x_did_reqs={
        "process_cmdline": "Command line used to create the new process or execute image",
        "process_path": "Directory Path of Process",
        "account": "account associated with process",
        "initiating_process_cmdline": "Command line used to run the process that initiated the event",
        "initiating_process_path": "Directory Path of Initiating Process"
    },
    x_did_ns_obj={
        "collection_methods": ["mde"],
        "operating_system": ["windows", "linux"]
    }
)


process_create_mde__windows_any = d2s.XDeltaDid(
    id=x_delta_did + str(uuid.uuid5(delta_namespace, "process_create-linux_any")),
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Process Creation Event From Any Linux OS",
    x_delta_did="process_create-windows_any",
    x_did_reqs={
        "process_cmdline": "Command line used to create the new process or execute image",
        "process_path": "Directory Path of Process",
        "account": "account associated with process",
        "initiating_process_cmdline": "Command line used to run the process that initiated the event",
        "initiating_process_path": "Directory Path of Initiating Process"
    },
    x_did_ns_obj={
        "collection_methods": ["mde"],
        "operating_system": ["windows"]
    }
)