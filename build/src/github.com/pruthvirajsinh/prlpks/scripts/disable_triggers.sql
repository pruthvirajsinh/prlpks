-- Disabling triggers also shuts off foreign key validation.
-- This script must be run as a superuser, however.
ALTER TABLE openpgp_pubkey     DISABLE TRIGGER ALL;
ALTER TABLE openpgp_pubkey_sig DISABLE TRIGGER ALL;
ALTER TABLE openpgp_sig        DISABLE TRIGGER ALL;
ALTER TABLE openpgp_subkey     DISABLE TRIGGER ALL;
ALTER TABLE openpgp_subkey_sig DISABLE TRIGGER ALL;
ALTER TABLE openpgp_uat        DISABLE TRIGGER ALL;
ALTER TABLE openpgp_uat_sig    DISABLE TRIGGER ALL;
ALTER TABLE openpgp_uid        DISABLE TRIGGER ALL;
ALTER TABLE openpgp_uid_sig    DISABLE TRIGGER ALL;

