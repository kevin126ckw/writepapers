CREATE TABLE "user"
(
    id            integer not null
        constraint id
            primary key autoincrement,
    username      TEXT    not null
        constraint user_pk
            unique,
    password      TEXT,
    name          TEXT,
    register_time integer
);

create index if not exists user_id_index
    on user (id);