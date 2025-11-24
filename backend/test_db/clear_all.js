import { open } from 'sqlite';
import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import readline from 'readline';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create readline interface for confirmation
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function askConfirmation(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

async function clearAllTables() {
  console.log('🗑️  Clear All Database Records\n');

  try {
    // Database file path
    const dbPath = path.join(__dirname, '../test_data/database.db');

    // Open database connection
    const db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    console.log('✅ Database connection established\n');

    // Get all tables
    const tables = await db.all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");

    if (tables.length === 0) {
      console.log('ℹ️  No tables found in database\n');
      await db.close();
      rl.close();
      return;
    }

    // Show current counts
    console.log('📊 Current Table Statistics:');
    for (const table of tables) {
      const result = await db.get(`SELECT COUNT(*) as count FROM ${table.name}`);
      console.log(`   - ${table.name}: ${result.count} rows`);
    }
    console.log('');

    // Ask for confirmation
    const confirmed = await askConfirmation('⚠️  Are you sure you want to DELETE ALL records from ALL tables? (y/N): ');

    if (!confirmed) {
      console.log('\n❌ Operation cancelled\n');
      await db.close();
      rl.close();
      return;
    }

    console.log('\n🔥 Deleting all records...\n');

    // Delete from all tables
    for (const table of tables) {
      await db.run(`DELETE FROM ${table.name}`);
      console.log(`✅ Cleared ${table.name}`);
    }

    // Reset auto-increment counters
    await db.run('DELETE FROM sqlite_sequence');
    console.log('✅ Reset auto-increment counters\n');

    // Show final counts
    console.log('📊 Final Table Statistics:');
    for (const table of tables) {
      const result = await db.get(`SELECT COUNT(*) as count FROM ${table.name}`);
      console.log(`   - ${table.name}: ${result.count} rows`);
    }
    console.log('');

    // Close connection
    await db.close();
    console.log('✅ Database connection closed');

    console.log('\n🎉 All records deleted successfully!\n');
  } catch (error) {
    console.error('❌ Operation failed:');
    console.error(error);
    process.exit(1);
  } finally {
    rl.close();
  }
}

// Run the clear operation
clearAllTables();
