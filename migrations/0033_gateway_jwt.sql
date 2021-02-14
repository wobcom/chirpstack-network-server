-- +migrate Up
alter table gateway
    add column jwt_id uuid;

-- +migrate Down
alter table gateway
    drop column jwt_id;
