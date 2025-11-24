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

async function clearOtpsTable() {
  console.log('🗑️  Clear OTP Records\n');

  try {
    // Database file path
    const dbPath = path.join(__dirname, '../data/database.db');

    // Open database connection
    const db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    console.log('✅ Database connection established\n');

    // Get current OTP count
    const beforeCount = await db.get('SELECT COUNT(*) as count FROM otps');

    console.log('📊 Current Statistics:');
    console.log(`   - OTP records: ${beforeCount.count}\n`);

    if (beforeCount.count === 0) {
      console.log('ℹ️  OTP table is already empty\n');
      await db.close();
      rl.close();
      return;
    }

    // Show sample of what will be deleted (first 5 records)
    const samples = await db.all('SELECT email, created_at FROM otps LIMIT 5');
    if (samples.length > 0) {
      console.log('🔍 Sample records to be deleted:');
      samples.forEach((record) => {
        const date = new Date(record.created_at).toLocaleString();
        console.log(`   - ${record.email} (created: ${date})`);
      });
      if (beforeCount.count > 5) {
        console.log(`   ... and ${beforeCount.count - 5} more\n`);
      } else {
        console.log('');
      }
    }

    // Ask for confirmation
    const confirmed = await askConfirmation('⚠️  Are you sure you want to DELETE ALL OTP records? (y/N): ');

    if (!confirmed) {
      console.log('\n❌ Operation cancelled\n');
      await db.close();
      rl.close();
      return;
    }

    console.log('\n🔥 Deleting OTP records...\n');

    // Delete all OTP records
    const result = await db.run('DELETE FROM otps');
    console.log(`✅ Deleted ${result.changes} OTP records`);

    // Reset auto-increment counter for otps table
    await db.run("DELETE FROM sqlite_sequence WHERE name='otps'");
    console.log('✅ Reset OTP auto-increment counter\n');

    // Get final count
    const afterCount = await db.get('SELECT COUNT(*) as count FROM otps');

    console.log('📊 Final Statistics:');
    console.log(`   - OTP records: ${afterCount.count}\n`);

    // Close connection
    await db.close();
    console.log('✅ Database connection closed');

    console.log('\n🎉 OTP records cleared successfully!\n');
  } catch (error) {
    console.error('❌ Operation failed:');
    console.error(error);
    process.exit(1);
  } finally {
    rl.close();
  }
}

// Run the clear operation
clearOtpsTable();
