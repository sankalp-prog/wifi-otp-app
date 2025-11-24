// Pseudocode for db/init.js

import { open } from 'sqlite';
import sqlite3 from 'sqlite3';
import fs from 'fs/promises';
import path from 'path';

// 1. Open/create database connection
const db = await open({
  filename: '../test_data/database.db', // Creates file if doesn't exist
  driver: sqlite3.Database,
});

// 2. Read schema.sql file
const schema = await fs.readFile('./schema.sql', 'utf8');

// 3. Execute schema (create tables)
await db.exec(schema);

// 4. Optionally add test data
// await db.run('INSERT INTO ...');

// 5. Close connection
await db.close();

console.log('✅ Database initialized successfully!');
