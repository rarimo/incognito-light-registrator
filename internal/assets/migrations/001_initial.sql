-- +migrate Up

create table document_sod
(
    id                   BIGSERIAL                   not null primary key,
    created_at           timestamp without time zone not null default current_timestamp,
    updated_at           timestamp without time zone not null default current_timestamp,
    dg15                 varchar(512)                not null, -- base64 encoded
    hash_algorithm       smallint                    not null, -- 0 - sha1, 1 - sha256, 2 - sha384, 3 - sha512
    signature_algorithm  smallint                    not null, -- 0 - rsa, 1 - rsapss, 2 - ecdsa, 3 - brainpool
    signed_attributes    varchar(256)                not null, -- hex encoded
    encapsulated_content varchar(1024)               not null, -- hex encoded
    signature            varchar(1024)               not null, -- hex encoded
    pem_file             varchar(4096)               not null,
    error_kind           smallint,                             -- 0 - signed attributes validation failed, 1 - PEM file parsing failed, 2 - PEM file validation failed, 3 - signature verification failed
    error                varchar(1024),                        -- error message
    unique (hash_algorithm, signature_algorithm, signed_attributes, encapsulated_content, signature, error_kind, error)
    -- We need to ensure that we won't store the same document with the same error multiple times.
    -- Perhaps the same document can fail verification with different errors
);

-- +migrate Down

drop table document_sod;
