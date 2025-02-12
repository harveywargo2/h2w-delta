import uuid
from stix2 import (CustomObject, utils, v21, ExtensionDefinition)
from stix2.properties import (
    StringProperty, ListProperty, TypeProperty, IDProperty,
    ReferenceProperty, TimestampProperty, DictionaryProperty
)
from delta2.stix.common import (delta_namespace, delta_identity, schema_base)


# x-delta-detection custom stix 2.1 SDO
_type = 'x-detection'


# extension-definition--567d6e9f-e8a5-554c-a134-f94ccaff5fd6
x_detection_ExtensionDefinitionSMO = ExtensionDefinition(
    id="extension-definition--" + str(uuid.uuid5(delta_namespace, _type)),
    created_by_ref=delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="x-detection",
    description="""
    This extension creates a custom stix 2.1 SDO that is used to represent x-detection objects.
    This object is a container for detection content & logic configs.
    """,
    schema=schema_base+"sdo/x-detection.json",
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
    ('valid_from', TimestampProperty(default=lambda: utils.NOW)),
    ('valid_until', TimestampProperty()),
    ('labels', ListProperty(StringProperty)),
    ('external_references', ListProperty(v21.ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
    ('x_detection_id', StringProperty(required=True)),
    ('x_detection_producer', StringProperty(required=True)),
    ('x_detection_category', StringProperty()),
    ('x_detection_info', DictionaryProperty()),
    ('x_detection_config', DictionaryProperty()),
], extension_name=x_detection_ExtensionDefinitionSMO.id)
class XDetection(object):
    pass

