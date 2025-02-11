import uuid
from stix2 import (CustomObject, utils, v21, ExtensionDefinition)
from stix2.properties import (
    StringProperty, ListProperty, TypeProperty, IDProperty, ReferenceProperty, TimestampProperty, DictionaryProperty
)
from delta2stix.common import (delta_namespace, delta_identity, schema_base)


# x-delta-data custom stix 2.1 SDO
_type = 'x-delta-data'


# extension-definition--e57837b7-9083-5d7b-bc58-83059e942f59
x_delta_data_ExtensionDefinitionSMO = ExtensionDefinition(
    id="extension-definition--" + str(uuid.uuid5(delta_namespace, _type)),
    created_by_ref=delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="x-data-source",
    description="""
    This extension creates a custom SDO that is used to represent x-delta-data objects.
    This object contains information about data sources & telemetry requirements for detecting delta patterns.
    """,
    schema=schema_base+"sdo/x-delta-data.json",
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
    ('labels', ListProperty(StringProperty)),
    ('external_references', ListProperty(v21.ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
    ('name', StringProperty()),
    ('description', StringProperty()),
    ('x_delta_data_id', StringProperty(required=True)),
    ('x_data_requirements', DictionaryProperty()),
    ('x_data_info', DictionaryProperty())
], extension_name=x_delta_data_ExtensionDefinitionSMO.id)
class XDeltaData(object):
    pass

