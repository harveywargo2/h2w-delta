import uuid
import stix2
import


# delta SMO
# extension-definition--f637f617-afeb-5b8c-bacd-537aebeb9154

delta_ExtensionDefinitionSMO = stix2.ExtensionDefinition(
    id="extension-definition--" + str(uuid.uuid5(delta_namespace, f"{delta}")),
    created_by_ref=delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="delta",
    description="This extension creates a new SDO that can be used to represent weaknesses (for CWEs).",
    schema=schema_base+"sdo/delta.json",
    version="1.0",
    extension_types=["new-sdo"]
)

