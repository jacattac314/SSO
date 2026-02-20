/**
 * Simple migration runner – reads SQL files from migrations directory
 * and applies them in order, tracking applied migrations in a dedicated table.
 */
import fs from 'fs';
import path from 'path';
import { getPool, closePool } from '../config/database';

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');

async function ensureMigrationsTable(): Promise<void> {
  const pool = getPool();
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id       SERIAL PRIMARY KEY,
      filename VARCHAR(255) NOT NULL UNIQUE,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function getAppliedMigrations(): Promise<Set<string>> {
  const pool = getPool();
  const result = await pool.query<{ filename: string }>(
    'SELECT filename FROM schema_migrations ORDER BY id'
  );
  return new Set(result.rows.map((r) => r.filename));
}

async function runMigrations(): Promise<void> {
  await ensureMigrationsTable();
  const applied = await getAppliedMigrations();

  const files = fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  const pool = getPool();
  for (const file of files) {
    if (applied.has(file)) {
      console.warn(`[migrate] Skipping already applied: ${file}`);
      continue;
    }

    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf-8');
    console.warn(`[migrate] Applying: ${file}`);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (filename) VALUES ($1)', [file]);
      await client.query('COMMIT');
      console.warn(`[migrate] Applied: ${file}`);
    } catch (err) {
      await client.query('ROLLBACK');
      console.error(`[migrate] Failed: ${file}`, err);
      throw err;
    } finally {
      client.release();
    }
  }
  console.warn('[migrate] All migrations complete.');
}

runMigrations()
  .then(() => closePool())
  .catch((err) => {
    console.error('[migrate] Fatal error', err);
    process.exit(1);
  });
