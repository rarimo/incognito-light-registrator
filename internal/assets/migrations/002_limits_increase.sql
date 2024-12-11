-- +migrate Up

alter table document_sod
        alter column dg15 type varchar(32760),
        alter column signed_attributes type varchar(65536),
        alter column encapsulated_content type varchar(65536),
        alter column signature type varchar(16384),
        alter column aa_signature type varchar(16384),
        alter column pem_file type varchar(65536),
        alter column error type varchar(16384);

-- +migrate Down

alter table document_sod
        alter column dg15 type varchar(512),
        alter column signed_attributes type varchar(512),
        alter column encapsulated_content type varchar(4096),
        alter column signature type varchar(4096),
        alter column aa_signature type varchar(4096),
        alter column pem_file type varchar(4096),
        alter column error type varchar(1024);
