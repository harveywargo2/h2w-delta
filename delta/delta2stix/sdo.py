from stix2 import (CustomObject, utils, v21)
from stix2.properties import (
    StringProperty, ListProperty, TypeProperty, IDProperty,
    ReferenceProperty, TimestampProperty, PatternProperty, OpenVocabProperty,
)
from stix2.v21.vocab import PATTERN_TYPE
from delta.delta2stix.extensions import (
    delta_ExtensionDefinitionSMO, delta_tier_ExtensionDefinitionSMO, delta_data_ExtensionDefinitionSMO
)


# delta custom object
_type = 'delta'
@CustomObject(_type, [
    ('delta', StringProperty()),
    ('delta_category', StringProperty()),
    ('delta_meta', ListProperty(StringProperty)),
    ('type', TypeProperty(_type, spec_version='2.1')),
    ('spec_version', StringProperty(fixed='2.1')),
    ('id', IDProperty(_type, spec_version='2.1')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
    ('created', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('modified', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('name', StringProperty(required=True)),
    ('description', StringProperty()),
    ('pattern', PatternProperty(required=True)),
    ('pattern_type', OpenVocabProperty(PATTERN_TYPE, required=True)),
    ('pattern_version', StringProperty()),
    ('external_references', ListProperty(v21.ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1')))
], extension_name=delta_ExtensionDefinitionSMO.id)
class Delta(object):
    pass


# delta-tier custom object
_type = 'delta-tier'
@CustomObject(_type, [
    ('type', TypeProperty(_type, spec_version='2.1')),
    ('spec_version', StringProperty(fixed='2.1')),
    ('id', IDProperty(_type, spec_version='2.1')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
    ('created', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('modified', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('name', StringProperty(required=True)),
    ('description', StringProperty()),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1')))
], extension_name=delta_tier_ExtensionDefinitionSMO.id)
class DeltaTier(object):
    pass


# delta-data custom object
_type = 'delta-data'
@CustomObject(_type, [
    ('type', TypeProperty(_type, spec_version='2.1')),
    ('spec_version', StringProperty(fixed='2.1')),
    ('id', IDProperty(_type, spec_version='2.1')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
    ('created', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('modified', TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('name', StringProperty(required=True)),
    ('description', StringProperty()),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1')))
], extension_name=delta_data_ExtensionDefinitionSMO.id)
class DeltaData(object):
    pass