-- liquibase formatted sql
-- changeset key_material_share_widen_recipient:1
-- ruhnu/pk/<base64 OpenSSH public key blob> recipients are ~149 characters
ALTER TABLE key_material_share
ALTER COLUMN recipient TYPE VARCHAR(255);
