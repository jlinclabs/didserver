CREATE TABLE IF NOT EXISTS chainlinks (
  id text PRIMARY KEY,
  seq bigserial UNIQUE,
  chainlink text NOT NULL UNIQUE,
  created timestamp DEFAULT current_timestamp
);
