create table if not exists chat_history
(
    "index" integer
        constraint chat_history_pk
            primary key,
    "from"  TEXT,
    "to"    TEXT,
    type    TEXT,
    message TEXT
);

create unique index if not exists chat_history_index
    on chat_history ("index");

