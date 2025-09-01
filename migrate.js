const { Pool } = require('pg');

// Railway automatically provides DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function migrate() {
  try {
    console.log('🗄️  Setting up database tables...');

    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        auth_type VARCHAR(20) DEFAULT 'guest' CHECK (auth_type IN ('guest', 'friend', 'premium')),
        daily_card_limit INTEGER DEFAULT 10,
        cards_generated_today INTEGER DEFAULT 0,
        api_calls_today INTEGER DEFAULT 0,
        last_reset_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Subjects table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subjects (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        prompt TEXT NOT NULL,
        total_cards INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Cards table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS cards (
        id SERIAL PRIMARY KEY,
        subject_id INTEGER REFERENCES subjects(id) ON DELETE CASCADE,
        front TEXT NOT NULL,
        back TEXT NOT NULL,
        difficulty VARCHAR(20) NOT NULL,
        category VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // User progress table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_card_progress (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        card_id INTEGER REFERENCES cards(id) ON DELETE CASCADE,
        correct_count INTEGER DEFAULT 0,
        incorrect_count INTEGER DEFAULT 0,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        next_review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        confidence_level FLOAT DEFAULT 0.5,
        UNIQUE(user_id, card_id)
      )
    `);

    // Rate limiting table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS rate_limits (
        id SERIAL PRIMARY KEY,
        ip_address INET NOT NULL,
        endpoint VARCHAR(100) NOT NULL,
        requests_count INTEGER DEFAULT 1,
        window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(ip_address, endpoint)
      )
    `);

    console.log('✅ Database tables created successfully!');
    
    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_user_cards ON user_card_progress(user_id);
      CREATE INDEX IF NOT EXISTS idx_subject_cards ON cards(subject_id);
      CREATE INDEX IF NOT EXISTS idx_user_subjects ON subjects(user_id);
      CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip_address, window_start);
    `);

    console.log('✅ Database indexes created successfully!');

  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
    console.log('🎉 Migration completed!');
    process.exit(0);
  }
}

if (require.main === module) {
  migrate();
}

module.exports = { migrate, pool };
