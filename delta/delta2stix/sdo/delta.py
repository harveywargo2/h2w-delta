from stix2 import (CustomObject, properties, utils, v21)
from delta.delta2stix.extensions import delta_ExtensionDefinitionSMO


_type = 'delta'
@CustomObject(_type, [
    ('delta', properties.StringProperty()),
    ('delta_category', properties.StringProperty()),
    ('delta_meta', properties.ListProperty(properties.StringProperty)),
    ('type', properties.TypeProperty(_type, spec_version='2.1')),
    ('spec_version', properties.StringProperty(fixed='2.1')),
    ('id', properties.IDProperty(_type, spec_version='2.1')),
    ('created_by_ref', properties.ReferenceProperty(valid_types='identity', spec_version='2.1')),
    ('created', properties.TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('modified', properties.TimestampProperty(default=lambda: utils.NOW, precision='millisecond', precision_constraint='min')),
    ('name', properties.StringProperty(required=True)),
    ('description', properties.StringProperty()),
    ('external_references', properties.ListProperty(v21.ExternalReference)),
    ('object_marking_refs', properties.ListProperty(properties.ReferenceProperty(
        valid_types='marking-definition', spec_version='2.1')))
], extension_name=delta_ExtensionDefinitionSMO.id)
class Delta(object):
    pass

