import uuid


# reserved UUID for generating UUIDv5s
delta_namespace = uuid.UUID("d0d00000-28f6-485e-851e-e52ba07a2091")
sco_namespace = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


# identity = identity--6c7d8a77-1bf5-5fd4-a66d-02d9955117d9
delta_identity = "identity--" + str(uuid.uuid5(delta_namespace, 'h2w-delta'))


schema_base = "https://raw.githubusercontent.com/harveywargo2/h2w-delta/refs/heads/main/delta/schemas/"
default_timestamp = "2018-01-01T00:00:00.000Z"

