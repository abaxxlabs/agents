export const ORDERS_PLAINTEXT_DDL = `
  CREATE TABLE IF NOT EXISTS orders_plaintext (
    id            SERIAL PRIMARY KEY,
    instrument    TEXT NOT NULL,
    side          TEXT NOT NULL CHECK (side IN ('BUY', 'SELL')),
    quantity      NUMERIC NOT NULL,
    price         NUMERIC NOT NULL,
    counterparty  TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'OPEN',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT '2026-01-01T00:00:00Z'
  );
`;

export const ORDERS_PLAINTEXT_SEED = `
  INSERT INTO orders_plaintext (instrument, side, quantity, price, counterparty, status, created_at) VALUES
    ('LNG-JKM-SEP26',  'BUY',  500,  12.45, 'Meridian Energy',   'OPEN',   '2026-01-01T00:00:00Z'),
    ('LNG-JKM-OCT26',  'SELL', 250,  12.80, 'Hokuto Gas',        'OPEN',   '2026-01-01T00:00:00Z'),
    ('NG-HH-SEP26',    'BUY',  1000, 3.215, 'Gulf Coast Trading','FILLED', '2026-01-01T00:00:00Z'),
    ('EU-CARBON-DEC26','BUY',  750,  88.10, 'Alpenwerk AG',      'OPEN',   '2026-01-01T00:00:00Z'),
    ('LNG-JKM-NOV26',  'SELL', 400,  13.05, 'Meridian Energy',   'OPEN',   '2026-01-01T00:00:00Z'),
    ('NG-HH-OCT26',    'SELL', 600,  3.410, 'Iberdrola Trading', 'CANCELLED', '2026-01-01T00:00:00Z'),
    ('EU-CARBON-SEP26','BUY',  320,  86.75, 'Nordvik Kraft',     'OPEN',   '2026-01-01T00:00:00Z'),
    ('LNG-JKM-DEC26',  'BUY',  150,  13.30, 'Hokuto Gas',        'OPEN',   '2026-01-01T00:00:00Z');
`;

// Per-request copy of the fixture. Literal IDs keep the local shape identical
// to the seeded public table without touching its sequence. A fixed timestamp
// keeps responses stable across requests.
export const ORDERS_PLAINTEXT_TEMP_DDL = `
  CREATE TEMP TABLE orders_plaintext (
    id            INTEGER PRIMARY KEY,
    instrument    TEXT NOT NULL,
    side          TEXT NOT NULL CHECK (side IN ('BUY', 'SELL')),
    quantity      NUMERIC NOT NULL,
    price         NUMERIC NOT NULL,
    counterparty  TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'OPEN',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT '2026-01-01T00:00:00Z'
  ) ON COMMIT DROP;
`;

export const ORDERS_PLAINTEXT_TEMP_SEED = `
  INSERT INTO orders_plaintext (id, instrument, side, quantity, price, counterparty, status, created_at) VALUES
    (1, 'LNG-JKM-SEP26',  'BUY',  500,  12.45, 'Meridian Energy',   'OPEN',   '2026-01-01T00:00:00Z'),
    (2, 'LNG-JKM-OCT26',  'SELL', 250,  12.80, 'Hokuto Gas',        'OPEN',   '2026-01-01T00:00:00Z'),
    (3, 'NG-HH-SEP26',    'BUY',  1000, 3.215, 'Gulf Coast Trading','FILLED', '2026-01-01T00:00:00Z'),
    (4, 'EU-CARBON-DEC26','BUY',  750,  88.10, 'Alpenwerk AG',      'OPEN',   '2026-01-01T00:00:00Z'),
    (5, 'LNG-JKM-NOV26',  'SELL', 400,  13.05, 'Meridian Energy',   'OPEN',   '2026-01-01T00:00:00Z'),
    (6, 'NG-HH-OCT26',    'SELL', 600,  3.410, 'Iberdrola Trading', 'CANCELLED', '2026-01-01T00:00:00Z'),
    (7, 'EU-CARBON-SEP26','BUY',  320,  86.75, 'Nordvik Kraft',     'OPEN',   '2026-01-01T00:00:00Z'),
    (8, 'LNG-JKM-DEC26',  'BUY',  150,  13.30, 'Hokuto Gas',        'OPEN',   '2026-01-01T00:00:00Z');
`;
