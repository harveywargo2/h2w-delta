import uuid
import stix2
from delta.delta2stix.common import delta_identity, delta_namespace, schema_base


# delta SDO
# extension-definition--f637f617-afeb-5b8c-bacd-537aebeb9154

delta_ExtensionDefinitionSMO = stix2.ExtensionDefinition(
    id="extension-definition--" + str(uuid.uuid5(delta_namespace, "delta")),
    created_by_ref=delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="delta",
    description="This extension creates a new SDO that can be used to represent delta's for detectable TTPs.",
    schema=schema_base+"sdo/delta.json",
    version="1.0",
    extension_types=["new-sdo"]
)


delta_tier_ExtensionDefinitionSMO = stix2.ExtensionDefinition(
    id="extension-definition--" + str(uuid.uuid5(delta_namespace, "delta-tier")),
    created_by_ref=delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="delta-tier",
    description="This extension creates a new SDO that can be used to represent the delta-tier",
    schema=schema_base+"sdo/delta_tier.json",
    version="1.0",
    extension_types=["new-sdo"]
)


delta_data_ExtensionDefinitionSMO = stix2.ExtensionDefinition(
    id="extension-definition--" + str(uuid.uuid5(delta_namespace, "delta-data")),
    created_by_ref=delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="delta-data",
    description="This extension creates a new SDO that can be used to represent the delta-data",
    schema=schema_base+"sdo/delta_data.json",
    version="1.0",
    extension_types=["new-sdo"]
)

