import uuid
from stix2 import (CustomObject, utils, ExtensionDefinition, v21)
from stix2.properties import (
    StringProperty, ListProperty, TypeProperty, IDProperty,
    ReferenceProperty, TimestampProperty, DictionaryProperty
)
from delta2.common import (delta_namespace, delta_identity, schema_base)


# x-delta-evidence custom stix 2.1 SDO
_type = 'x-delta-eid'


# extension-definition--cb878c8d-2c1d-5d9c-a2b3-d3f45dc63f2e
x_delta_eid_ExtensionDefinitionSMO = ExtensionDefinition(
    id="extension-definition--" + str(uuid.uuid5(delta_namespace, _type)),
    created_by_ref=delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    name="x-delta-eid",
    description="""
    This extension creates a custom stix 2.1 SDO that is used to represent x-delta-eid objects.
    The delta-eid stands for Delta Evidence ID and follows format of "shortname-eid0000".
    """,
    schema=schema_base+"sdo/x-delta-eid.json",
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
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
    ('external_references', ListProperty(v21.ExternalReference)),
    ('description', StringProperty()),
    ('x_delta_evidence_id', StringProperty(required=True)),
    ('x_evidence_obj', DictionaryProperty()),
    ('x_evidence_meta', DictionaryProperty()),
], extension_name=x_delta_eid_ExtensionDefinitionSMO.id)
class XDeltaEvidenceId(object):
    pass

