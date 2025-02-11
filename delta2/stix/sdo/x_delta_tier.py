import uuid
from stix2 import (CustomObject, utils, ExtensionDefinition)
from stix2.properties import (
    StringProperty, ListProperty, TypeProperty, IDProperty,
    ReferenceProperty, TimestampProperty, DictionaryProperty
)

from delta2stix.common import (delta_namespace, delta_identity, schema_base)


# x-delta-tier custom stix 2.1 SDO
_type = 'x-delta-tier'


# extension-definition--5d6da79e-e087-5ae4-ad2b-7b854d3d71c6
x_delta_tier_ExtensionDefinitionSMO = ExtensionDefinition(
    id="extension-definition--" + str(uuid.uuid5(delta_namespace, _type)),
    created_by_ref=delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="x-delta-tier",
    description="""
    This extension creates a custom stix 2.1 SDO used to represent x-delta-tier objects.
    This object contains scoring/calibration data for applying a tier/rating to x-delta-pid.
    """,
    schema=schema_base+"sdo/x-delta-tier.json",
    version="1.0",
    extension_types=["new-sdo"]
)


@CustomObject(_type, [
    ('type', TypeProperty(_type, spec_version='2.1')),
    ('spec_version', StringProperty(fixed='2.1')),
    ('id', IDProperty(_type, spec_version='2.1')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
    ('created', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('modified', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('name', StringProperty()),
    ('x_delta_tier', StringProperty(required=True)),
    ('x_calibration_info', DictionaryProperty())
], extension_name=x_delta_tier_ExtensionDefinitionSMO.id)
class XDeltaTier(object):
    pass

