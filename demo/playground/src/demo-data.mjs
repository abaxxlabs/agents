export const ORDERS_PLAINTEXT_DDL = `
  CREATE TABLE IF NOT EXISTS orders_plaintext (
    id            SERIAL PRIMARY KEY,
    instrument    TEXT NOT NULL,
    side          TEXT NOT NULL CHECK (side IN ('BUY', 'SELL')),
    quantity      NUMERIC NOT NULL,
    price         NUMERIC NOT NULL,
    counterparty  TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'OPEN',
    created_at    TIMESTAMPTZ DEFAULT NOW()
  );
`;

export const ORDERS_PLAINTEXT_SEED = `
  INSERT INTO orders_plaintext (instrument, side, quantity, price, counterparty, status) VALUES
    ('LNG-JKM-SEP26',  'BUY',  500,  12.45, 'Meridian Energy',   'OPEN'),
    ('LNG-JKM-OCT26',  'SELL', 250,  12.80, 'Hokuto Gas',        'OPEN'),
    ('NG-HH-SEP26',    'BUY',  1000, 3.215, 'Gulf Coast Trading','FILLED'),
    ('EU-CARBON-DEC26','BUY',  750,  88.10, 'Alpenwerk AG',      'OPEN'),
    ('LNG-JKM-NOV26',  'SELL', 400,  13.05, 'Meridian Energy',   'OPEN'),
    ('NG-HH-OCT26',    'SELL', 600,  3.410, 'Iberdrola Trading', 'CANCELLED'),
    ('EU-CARBON-SEP26','BUY',  320,  86.75, 'Nordvik Kraft',     'OPEN'),
    ('LNG-JKM-DEC26',  'BUY',  150,  13.30, 'Hokuto Gas',        'OPEN');
`;
