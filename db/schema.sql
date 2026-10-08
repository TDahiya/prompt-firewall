CREATE TABLE IF NOT EXISTS checks (
    id            BIGSERIAL PRIMARY KEY,
    text          TEXT NOT NULL,
    verdict       VARCHAR(10) NOT NULL,
    category      VARCHAR(30) NOT NULL,
    confidence    FLOAT NOT NULL,
    matched_pattern TEXT,
    layer         VARCHAR(10),
    latency_ms    FLOAT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS checks_verdict_idx ON checks (verdict);
CREATE INDEX IF NOT EXISTS checks_category_idx ON checks (category);
CREATE INDEX IF NOT EXISTS checks_created_at_idx ON checks (created_at DESC);
