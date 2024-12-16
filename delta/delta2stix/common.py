import uuid


# define UUID for generating UUIDv5s
delta_namespace = uuid.UUID("d0d00000-28f6-485e-851e-e52ba07a2091")


# common objects
# identity = identity--6c7d8a77-1bf5-5fd4-a66d-02d9955117d9
identity_object = "h2w-delta"
delta_identity = "identity--" + str(uuid.uuid5(delta_namespace, f"{identity_object}"))


schema_base = "https://raw.githubusercontent.com/harveywargo2/h2w-dtech/refs/heads/main/dtech/delta/schemas/"
