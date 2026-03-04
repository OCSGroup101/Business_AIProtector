-- OpenClaw PostgreSQL initialization
-- Runs once when the container is first created.

-- Create Keycloak database for Keycloak service
CREATE DATABASE keycloak OWNER openclaw;

-- Enable required extensions
\c openclaw;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create the platform role with limited privileges
-- API connections use this role; RLS enforces tenant isolation
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openclaw_api') THEN
        CREATE ROLE openclaw_api LOGIN PASSWORD 'openclaw_api_dev';
    END IF;
END $$;

GRANT CONNECT ON DATABASE openclaw TO openclaw_api;
GRANT USAGE ON SCHEMA public TO openclaw_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO openclaw_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO openclaw_api;
