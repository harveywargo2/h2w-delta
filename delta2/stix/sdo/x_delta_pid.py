import uuid
from stix2 import (CustomObject, utils, v21, ExtensionDefinition)
from stix2.properties import (
    ListProperty, TypeProperty, IDProperty, DictionaryProperty, StringProperty, ReferenceProperty,
    TimestampProperty
)
from delta2.common import (delta_namespace, delta_identity, schema_base)


# x-delta-pid custom stix 2.1 SDO
_type = 'x-delta-pid'


# extension-definition--cb23d54d-8332-524f-a0cc-cb405141948c
x_delta_pid_ExtensionDefinitionSMO = ExtensionDefinition(
    id="extension-definition--" + str(uuid.uuid5(delta_namespace, _type)),
    created_by_ref=delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="x-delta-pid",
    description="""
    This extension creates a custom stix 2.1 SDO used to represent x-delta-pid objects.
    The delta-pid stands for Delta Pattern ID and follows format of "shortname-pid0000".
    """,
    schema=schema_base+"sdo/x-delta-pid.json",
    version="1.0",
    extension_types=["new-sdo"]
)


@CustomObject(_type, [
    ('type', TypeProperty(_type, spec_version='2.1')),
    ('spec_version', StringProperty(fixed='2.1')),
    ('id', IDProperty(_type, spec_version='2.1')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
    ('valid_from', TimestampProperty(default=lambda: utils.NOW)),
    ('valid_until', TimestampProperty()),
    ('labels', ListProperty(StringProperty)),
    ('external_references', ListProperty(v21.ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
    ('name', StringProperty()),
    ('description', StringProperty()),
    ('created', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('modified', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('x_delta_pid', StringProperty(required=True)),
    ('x_pid_category', StringProperty()),
    ('x_pid_ns_obj', DictionaryProperty())
], extension_name=x_delta_pid_ExtensionDefinitionSMO.id)
class XDeltaPid(object):
    pass

