import uuid
from stix2 import (CustomObject, utils, v21, ExtensionDefinition)
from stix2.properties import (
    StringProperty, ListProperty, TypeProperty, IDProperty,
    ReferenceProperty, TimestampProperty, DictionaryProperty
)
from delta2.stix.common import (delta_namespace, delta_identity, schema_base)


# x-simulation custom stix 2.1 SDO
_type = 'x-simulation'


# extension-definition--69a6aff6-ec33-520f-868e-f951c645faf2
x_simulation_ExtensionDefinitionSMO = ExtensionDefinition(
    id="extension-definition--" + str(uuid.uuid5(delta_namespace, _type)),
    created_by_ref=delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="x-simulation",
    description="""
    This extension creates a custom stix 2.1 SDO that is used to represent x-simulation objects.
    This object is a container for simulation test data.
    """,
    schema=schema_base+"sdo/x-simulation.json",
    version="1.0",
    extension_types=["new-sdo"]
)


@CustomObject(_type, [
    ('type', TypeProperty(_type, spec_version='2.1')),
    ('spec_version', StringProperty(fixed='2.1')),
    ('id', IDProperty(_type, spec_version='2.1')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
    ('created', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('modified', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('name', StringProperty()),
    ('description', StringProperty()),
    ('labels', ListProperty(StringProperty)),
    ('external_references', ListProperty(v21.ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
    ('x_simulation_id', StringProperty(required=True)),
    ('x_simulation_producer', StringProperty()),
    ('x_simulation_info', DictionaryProperty()),
    ('x_simulation_config', DictionaryProperty()),
], extension_name=x_simulation_ExtensionDefinitionSMO.id)
class XSimulation(object):
    pass

