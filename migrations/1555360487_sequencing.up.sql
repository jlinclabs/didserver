ALTER TABLE IF EXISTS didstore ADD COLUMN sequence bigserial UNIQUE;

DROP TABLE IF EXISTS chainlinks;
