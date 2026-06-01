# SQL & Databases Reference — Pair Programmer

## Query Correctness

**Always use parameterized queries — no exceptions:**
```python
# NEVER
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ALWAYS
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**Understand NULL semantics:**
```sql
-- NULL comparisons never return TRUE with =
WHERE status = NULL    -- always empty result set
WHERE status IS NULL   -- correct

-- NULL in aggregates: COUNT(*) vs COUNT(col)
SELECT COUNT(*)        -- counts all rows
SELECT COUNT(email)    -- excludes NULLs
```

**JOIN types matter — be explicit:**
```sql
INNER JOIN  -- only matching rows on both sides
LEFT JOIN   -- all left rows + matching right (NULL if no match)
RIGHT JOIN  -- all right rows + matching left
FULL OUTER JOIN -- all rows from both sides
CROSS JOIN  -- cartesian product (usually a mistake if unintentional)
```

---

## Performance

**Indexes: what triggers them, what doesn't:**
```sql
-- Index on (last_name, first_name)
WHERE last_name = 'Smith'              -- ✓ uses index (leading column)
WHERE last_name = 'Smith' AND first_name = 'John'  -- ✓ uses full index
WHERE first_name = 'John'             -- ✗ skips index (not leading column)

-- Functions on indexed columns kill index usage
WHERE LOWER(email) = 'test@example.com'  -- ✗ full table scan
-- Fix: index on LOWER(email), or store pre-lowercased
```

**N+1 query detection:**
```python
# N+1: one query per user (100 users = 101 queries)
users = User.query.all()
for user in users:
    print(user.orders.count())  # new query each iteration

# Fix: eager load or a single JOIN query
users = User.query.options(joinedload(User.orders)).all()
```

**EXPLAIN / EXPLAIN ANALYZE:**
```sql
EXPLAIN ANALYZE SELECT ...;
-- Look for: Seq Scan on large tables, high actual rows vs estimated rows
-- Want: Index Scan, low actual rows
```

**Pagination — keyset vs OFFSET:**
```sql
-- Offset pagination (gets slower as offset grows)
SELECT * FROM posts ORDER BY id LIMIT 20 OFFSET 10000;

-- Keyset pagination (consistent O(log n))
SELECT * FROM posts WHERE id > :last_seen_id ORDER BY id LIMIT 20;
```

---

## Transactions

**Use transactions for multi-step mutations:**
```sql
BEGIN;
  UPDATE accounts SET balance = balance - 100 WHERE id = 1;
  UPDATE accounts SET balance = balance + 100 WHERE id = 2;
  -- If either fails, ROLLBACK rolls back both
COMMIT;
```

**Isolation levels (PostgreSQL default: READ COMMITTED):**
- `READ COMMITTED` — sees committed data at statement start (good default)
- `REPEATABLE READ` — consistent snapshot for transaction duration (prevents non-repeatable reads)
- `SERIALIZABLE` — prevents all anomalies, highest cost

**Deadlock prevention — always acquire locks in the same order.**

**Optimistic locking for high-contention rows:**
```sql
-- Add a version column
UPDATE items SET stock = stock - 1, version = version + 1
WHERE id = 42 AND version = :expected_version;
-- Check affected rows: 0 = someone else updated, retry
```

---

## Schema Design

**Use appropriate data types:**
```sql
-- Prefer
id UUID DEFAULT gen_random_uuid()   -- globally unique, no contention
created_at TIMESTAMPTZ              -- always store timezone-aware timestamps
amount NUMERIC(15, 2)               -- exact for money, never FLOAT
status VARCHAR(20)                  -- or ENUM if values are fixed
flags JSONB                         -- for flexible structured data (PostgreSQL)
```

**Don't use FLOAT for money — ever.** Floating point has rounding errors. Use `NUMERIC`/`DECIMAL`.

**Soft deletes — consider the trade-offs:**
```sql
-- Soft delete: keeps history but pollutes all queries
deleted_at TIMESTAMPTZ DEFAULT NULL

-- Every query now needs: WHERE deleted_at IS NULL
-- Consider: archive table, event sourcing, or just hard delete
```

**Foreign keys with explicit cascade behavior:**
```sql
REFERENCES users(id) ON DELETE CASCADE   -- delete orphans
REFERENCES users(id) ON DELETE SET NULL  -- orphan gets NULL
REFERENCES users(id) ON DELETE RESTRICT  -- prevent if children exist
```

---

## Migrations

**Migrations must be:**
1. **Reversible** — write both `up` and `down`
2. **Non-destructive on first deploy** — never `DROP COLUMN` in the same migration as removing code that reads it
3. **Zero-downtime aware** — see patterns below

**Zero-downtime migration patterns:**
```sql
-- Adding a column: safe
ALTER TABLE users ADD COLUMN bio TEXT;

-- Adding a NOT NULL column: unsafe (fails if table is non-empty)
-- Do instead: add nullable → backfill → add constraint
ALTER TABLE users ADD COLUMN bio TEXT;
UPDATE users SET bio = '' WHERE bio IS NULL;
ALTER TABLE users ALTER COLUMN bio SET NOT NULL;

-- Renaming a column: never do directly
-- Step 1: add new column
-- Step 2: dual-write to both in code
-- Step 3: backfill
-- Step 4: switch reads to new column
-- Step 5: drop old column (separate deploy)

-- Adding an index: use CONCURRENTLY (PostgreSQL) to avoid table lock
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
```

---

## Common Mistakes

**Selecting `SELECT *` in production code:** Fragile, may return unexpected data, prevents covering indexes.

**Missing index on foreign keys:** PostgreSQL doesn't auto-create indexes for FKs; joins will be slow.

**Storing JSON blobs for structured, queryable data:** Use proper columns + indexes; JSONB only when structure is genuinely variable.

**`GROUP BY` with non-aggregate columns not in GROUP BY:** Some databases silently return arbitrary values (MySQL); PostgreSQL errors correctly.

**Relying on `ORDER BY` without a unique tiebreaker:** Pagination becomes non-deterministic.

---

## Security

- **SQL injection:** Parameterized queries, always. No exceptions for "trusted" inputs.
- **Principle of least privilege:** Application user should not have `DROP`, `CREATE`, `GRANT` permissions
- **Connection strings:** In environment variables or secrets manager — never in code
- **Sensitive data:** Hash passwords (bcrypt/argon2); encrypt PII at rest; never log passwords or tokens
- **Audit log:** For regulated data, log who changed what and when (separate audit table or CDC)
