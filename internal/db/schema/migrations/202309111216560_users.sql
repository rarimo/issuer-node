
-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
    id bigserial PRIMARY KEY,
    login text NOT NULL,
    password text NOT NULL,
    did text NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
-- +goose StatementEnd