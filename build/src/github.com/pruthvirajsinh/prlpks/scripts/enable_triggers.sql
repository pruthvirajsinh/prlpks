-- Disabling triggers also shuts off foreign key validation.
-- This script must be run as a superuser, however.
ALTER TABLE openpgp_pubkey     ENABLE TRIGGER ALL;
ALTER TABLE openpgp_pubkey_sig ENABLE TRIGGER ALL;
ALTER TABLE openpgp_sig        ENABLE TRIGGER ALL;
ALTER TABLE openpgp_subkey     ENABLE TRIGGER ALL;
ALTER TABLE openpgp_subkey_sig ENABLE TRIGGER ALL;
ALTER TABLE openpgp_uat        ENABLE TRIGGER ALL;
ALTER TABLE openpgp_uat_sig    ENABLE TRIGGER ALL;
ALTER TABLE openpgp_uid        ENABLE TRIGGER ALL;
ALTER TABLE openpgp_uid_sig    ENABLE TRIGGER ALL;

