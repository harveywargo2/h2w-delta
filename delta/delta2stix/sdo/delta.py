from stix2 import (CustomObject, utils, v21)
from stix2.properties import (
    StringProperty, ListProperty, TypeProperty, IDProperty,
    ReferenceProperty, TimestampProperty, PatternProperty, OpenVocabProperty,
)
from stix2.v21.vocab import PATTERN_TYPE
from delta.delta2stix.extensions import delta_ExtensionDefinitionSMO


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

