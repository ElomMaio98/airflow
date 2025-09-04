SELECT 'CREATE DATABASE airflow'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'airflow')\gexec
SELECT 'CREATE DATABASE app'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'airflow')\gexec
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE IF NOT EXISTS security_findings ()
