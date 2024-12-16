-- +migrate Up

alter table document_sod
    add column raw_sod varchar(262144);

-- +migrate Down

alter table document_sod
    drop column raw_sod;
