-- liquibase formatted sql

-- changeset andres:1-1
CREATE TABLE public.jwt_token
(
    jwt_uuid         uuid PRIMARY KEY,
    session_id       character varying(36)       NOT NULL,
    expiration_date  timestamp without time zone NOT NULL,
    issued_date      timestamp without time zone NOT NULL,
    is_blacklisted   boolean DEFAULT false,
    blacklisted_date timestamp without time zone
);

CREATE SEQUENCE public.sessions_sess_id_seq;

CREATE TABLE public.sessions
(
    sess_id          bigint PRIMARY KEY,
    session_id       text,
    personal_code    text,
    valid_from       timestamp without time zone,
    valid_to         timestamp without time zone,
    givenname        text,
    surname          text,
    channel          varchar(30),
    ip               text,
    params           text,
    rights           text,
    created          timestamp without time zone,
    last_modified    timestamp without time zone,
    username         varchar(11),
    browser          varchar,
    loginlevel       varchar,
    mobile_number    text,
    certificate_type text,
    authenticated_as varchar,
    hash             varchar
);

CREATE UNIQUE INDEX sessions_session_id_idx ON public.sessions USING btree (session_id);
CREATE INDEX sessions_valid_to_idx ON public.sessions USING btree (valid_to);

COMMENT ON TABLE public.sessions IS 'Sessioonide tabel';
COMMENT ON COLUMN public.sessions.session_id IS 'Sessiooni identifikaator.';
COMMENT ON COLUMN public.sessions.personal_code IS 'Isikukood, loetakse algselt ID-kaardilt või sisestatakse välise osapoole poolt.';
COMMENT ON COLUMN public.sessions.valid_from IS 'Sessiooni kehtivuse algus.';
COMMENT ON COLUMN public.sessions.valid_to IS 'Sessiooni kehtivuse lõpp.';
COMMENT ON COLUMN public.sessions.givenname IS 'Kasutaja eesnimi.';
COMMENT ON COLUMN public.sessions.surname IS 'Kasutaja perekonnanimi.';
COMMENT ON COLUMN public.sessions.channel IS 'Kanal, mille kaudu sessioon loodi.';
COMMENT ON COLUMN public.sessions.ip IS 'Kasutaja IP aadress.';
COMMENT ON COLUMN public.sessions.params IS 'Kasutaja sessiooniparameetrid stringi kujul massiivis.';
COMMENT ON COLUMN public.sessions.rights IS 'Komadega eraldatud loetelu kasutaja õigustest.';
COMMENT ON COLUMN public.sessions.created IS 'Kirje loomise aeg.';
COMMENT ON COLUMN public.sessions.last_modified IS 'Kirje muutmise aeg.';
COMMENT ON COLUMN public.sessions.username IS 'Kirje looja või viimase muutja isikukood.';
COMMENT ON COLUMN public.sessions.browser IS 'Kasutaja user agent.';
COMMENT ON COLUMN public.sessions.loginlevel IS 'Kasutaja usaldatavuse tase.';
COMMENT ON COLUMN public.sessions.mobile_number IS 'M-IDga sisselogimiseks kasutatud mobiiltelefoni number.';
COMMENT ON COLUMN public.sessions.certificate_type IS 'Sertifikaadi tüüp';

-- changeset mobile app refresh token:1-1

CREATE TABLE public.refresh_token
(
    refresh_token_uuid uuid PRIMARY KEY,
    session_id         character varying(36)       NOT NULL,
    value              character varying(400)      NOT NULL,
    expires_at         timestamp without time zone NOT NULL,
    issued_at          timestamp without time zone NOT NULL,
    invalidated        boolean DEFAULT false,
    invalidated_at     timestamp without time zone
);