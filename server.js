require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;

// Database connection with retry logic
const createPool = () => {
  console.log('🔍 Environment check:');
  console.log('  NODE_ENV:', process.env.NODE_ENV);
  console.log('  DATABASE_URL exists:', !!process.env.DATABASE_URL);
  console.log('  DATABASE_URL length:', process.env.DATABASE_URL?.length || 0);
  console.log('  CLAUDE_API_KEY exists:', !!process.env.CLAUDE_API_KEY);
  console.log('  JWT_SECRET:', process.env.JWT_SECRET?.substring(0, 10) + '...');
  
  if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL environment variable is not set');
    console.error('Available env vars:', Object.keys(process.env).filter(key => 
      key.includes('DATABASE') || key.includes('POSTGRES') || key.includes('PG')
    ));
    process.exit(1);
  }

  return new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  });
};

let pool;

// Wait for database connection with retries
const waitForDatabase = async (maxRetries = 10, delay = 5000) => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      console.log(`🔄 Attempting to connect to database (attempt ${i + 1}/${maxRetries})...`);
      pool = createPool();
      
      // Test the connection
      const client = await pool.connect();
      await client.query('SELECT NOW()');
      client.release();
      
      console.log('✅ Database connection established!');
      return true;
    } catch (error) {
      console.error(`❌ Database connection failed (attempt ${i + 1}):`, error.message);
      
      if (pool) {
        await pool.end();
      }
      
      if (i < maxRetries - 1) {
        console.log(`⏳ Waiting ${delay/1000}s before retry...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  console.error('❌ Could not connect to database after maximum retries');
  return false;
};

// Auto-migration function
const runMigrations = async () => {
  try {
    console.log('🗄️  Running database migrations...');

    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        auth_type VARCHAR(20) DEFAULT 'guest' CHECK (auth_type IN ('guest', 'friend', 'premium', 'admin')),
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

    // Update auth_type constraint to include 'admin'
    await pool.query(`
      DO $$
      BEGIN
        -- Drop existing constraint if it exists
        IF EXISTS (SELECT 1 FROM information_schema.table_constraints
                  WHERE constraint_name = 'users_auth_type_check'
                  AND table_name = 'users'
                  AND constraint_type = 'CHECK') THEN
          ALTER TABLE users DROP CONSTRAINT users_auth_type_check;
        END IF;

        -- Add updated constraint
        ALTER TABLE users ADD CONSTRAINT users_auth_type_check
        CHECK (auth_type IN ('guest', 'friend', 'premium', 'admin'));
      END $$;
    `);

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_user_cards ON user_card_progress(user_id);
      CREATE INDEX IF NOT EXISTS idx_subject_cards ON cards(subject_id);
      CREATE INDEX IF NOT EXISTS idx_user_subjects ON subjects(user_id);
      CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip_address, window_start);
    `);

    console.log('✅ Database migrations completed successfully!');
    
    // Verify tables were created
    const result = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name;
    `);
    
    console.log('📋 Created tables:', result.rows.map(row => row.table_name).join(', '));
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  }
};

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting - 10 requests per hour per IP
const generalLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: { error: 'Too many requests, please try again later.' }
});

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    
    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Admin authorization middleware
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.auth_type !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Reset daily limits if needed
const resetDailyLimitsIfNeeded = async (user) => {
  const today = new Date().toISOString().split('T')[0];
  
  if (user.last_reset_date !== today) {
    await pool.query(`
      UPDATE users 
      SET cards_generated_today = 0, api_calls_today = 0, last_reset_date = $1 
      WHERE id = $2
    `, [today, user.id]);
    
    user.cards_generated_today = 0;
    user.api_calls_today = 0;
  }
  
  return user;
};

// Check if user can make API calls
const checkApiLimits = (user) => {
  const limits = {
    guest: { apiCalls: 2, cards: 10 },
    friend: { apiCalls: 5, cards: 100 },
    premium: { apiCalls: Infinity, cards: Infinity }
  };
  
  const userLimits = limits[user.auth_type] || limits.guest;
  
  return {
    canMakeCall: user.api_calls_today < userLimits.apiCalls,
    canGenerateCards: user.cards_generated_today < userLimits.cards,
    remainingCalls: userLimits.apiCalls - user.api_calls_today,
    remainingCards: userLimits.cards - user.cards_generated_today
  };
};

// Health check
app.get('/', (req, res) => {
  res.json({ 
    message: 'Claude Flashcards Backend is running!',
    timestamp: new Date().toISOString(),
    database: pool ? 'connected' : 'not connected'
  });
});

// Database health check
app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ 
      status: 'healthy', 
      database: 'connected',
      timestamp: result.rows[0].now
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'unhealthy', 
      database: 'error',
      error: error.message 
    });
  }
});

// User registration
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Check if user exists
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const result = await pool.query(`
      INSERT INTO users (email, password_hash, auth_type, daily_card_limit) 
      VALUES ($1, $2, 'guest', 10) 
      RETURNING id, email, auth_type, daily_card_limit
    `, [email, passwordHash]);

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      message: 'User created successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        authType: user.auth_type,
        dailyLimit: user.daily_card_limit
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Find user
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update daily limits if needed
    await resetDailyLimitsIfNeeded(user);

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      token,
      user: {
        id: user.id,
        email: user.email,
        authType: user.auth_type,
        dailyLimit: user.daily_card_limit,
        cardsToday: user.cards_generated_today,
        apiCallsToday: user.api_calls_today
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get user subjects
app.get('/subjects', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*, COUNT(c.id) as card_count 
      FROM subjects s 
      LEFT JOIN cards c ON s.id = c.subject_id 
      WHERE s.user_id = $1 
      GROUP BY s.id 
      ORDER BY s.created_at DESC
    `, [req.user.id]);

    res.json({ subjects: result.rows });
  } catch (error) {
    console.error('Get subjects error:', error);
    res.status(500).json({ error: 'Failed to get subjects' });
  }
});

// Create new subject
app.post('/subjects', authenticateToken, async (req, res) => {
  try {
    const { name, prompt } = req.body;

    if (!name || !prompt) {
      return res.status(400).json({ error: 'Name and prompt required' });
    }

    const result = await pool.query(`
      INSERT INTO subjects (user_id, name, prompt) 
      VALUES ($1, $2, $3) 
      RETURNING *
    `, [req.user.id, name, prompt]);

    res.json({ subject: result.rows[0] });
  } catch (error) {
    console.error('Create subject error:', error);
    res.status(500).json({ error: 'Failed to create subject' });
  }
});

// Update subject
app.put('/subjects/:subjectId', authenticateToken, async (req, res) => {
  try {
    const { subjectId } = req.params;
    const { name, prompt } = req.body;

    if (!name || !prompt) {
      return res.status(400).json({ error: 'Name and prompt required' });
    }

    // Check if subject belongs to user
    const checkResult = await pool.query(
      'SELECT id FROM subjects WHERE id = $1 AND user_id = $2', 
      [subjectId, req.user.id]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Subject not found' });
    }

    // Update the subject
    const result = await pool.query(`
      UPDATE subjects 
      SET name = $1, prompt = $2
      WHERE id = $3 AND user_id = $4
      RETURNING *
    `, [name, prompt, subjectId, req.user.id]);

    res.json({ subject: result.rows[0] });
  } catch (error) {
    console.error('Update subject error:', error);
    res.status(500).json({ error: 'Failed to update subject' });
  }
});

// Generate flashcards for a subject
app.post('/subjects/:subjectId/generate-cards', generalLimiter, authenticateToken, async (req, res) => {
  try {
    const { subjectId } = req.params;

    // Check if subject belongs to user
    const subjectResult = await pool.query(
      'SELECT * FROM subjects WHERE id = $1 AND user_id = $2', 
      [subjectId, req.user.id]
    );

    if (subjectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Subject not found' });
    }

    const subject = subjectResult.rows[0];

    // Reset daily limits if needed
    const user = await resetDailyLimitsIfNeeded(req.user);

    // Check limits
    const limits = checkApiLimits(user);
    if (!limits.canMakeCall) {
      return res.status(429).json({ 
        error: `Daily API limit reached. Try again tomorrow or upgrade your account.`,
        remainingCalls: limits.remainingCalls
      });
    }

    if (!CLAUDE_API_KEY) {
      return res.status(500).json({ error: 'Claude API key not configured' });
    }

    console.log('🚀 Generating flashcards for subject:', subject.name);

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-3-5-sonnet-20241022',
        max_tokens: 3000,
        messages: [{
          role: 'user',
          content: `Generate 25 flashcards for: "${subject.prompt}"

Format as JSON array with this exact structure:
[
  {
    "front": "Question or term to translate",
    "back": "Answer or translation", 
    "difficulty": "easy|medium|hard",
    "category": "category name"
  }
]

Make the flashcards appropriate for the level and varied in difficulty (mix of easy, medium, hard). Only return the JSON array, no other text.`
        }]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ Claude API Error:', response.status, errorText);
      return res.status(response.status).json({ 
        error: `Claude API error: ${response.status}` 
      });
    }

    const data = await response.json();
    const content = data.content[0].text;
    
    // Extract JSON from Claude's response
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (!jsonMatch) {
      console.error('❌ Could not parse JSON from:', content);
      return res.status(500).json({ error: 'Could not parse flashcards from Claude response' });
    }

    const cards = JSON.parse(jsonMatch[0]);
    console.log('✅ Generated', cards.length, 'flashcards');

    // Save cards to database
    const cardInsertPromises = cards.map(card => 
      pool.query(`
        INSERT INTO cards (subject_id, front, back, difficulty, category) 
        VALUES ($1, $2, $3, $4, $5) 
        RETURNING *
      `, [subjectId, card.front, card.back, card.difficulty, card.category])
    );

    const cardResults = await Promise.all(cardInsertPromises);
    const savedCards = cardResults.map(result => result.rows[0]);

    // Update user's daily counters
    await pool.query(`
      UPDATE users 
      SET api_calls_today = api_calls_today + 1, 
          cards_generated_today = cards_generated_today + $1 
      WHERE id = $2
    `, [cards.length, req.user.id]);

    // Update subject card count
    await pool.query(`
      UPDATE subjects 
      SET total_cards = (SELECT COUNT(*) FROM cards WHERE subject_id = $1) 
      WHERE id = $1
    `, [subjectId]);

    res.json({ 
      flashcards: savedCards,
      remainingCalls: limits.remainingCalls - 1,
      remainingCards: limits.remainingCards - cards.length
    });

  } catch (error) {
    console.error('🔥 Generate cards error:', error);
    res.status(500).json({ error: 'Failed to generate flashcards: ' + error.message });
  }
});

// Get cards for study session (spaced repetition)
app.get('/subjects/:subjectId/study', authenticateToken, async (req, res) => {
  try {
    const { subjectId } = req.params;
    const limit = parseInt(req.query.limit) || 20;

    // Get cards due for review, ordered by next_review_date
    const result = await pool.query(`
      SELECT c.*, 
             COALESCE(ucp.correct_count, 0) as correct_count,
             COALESCE(ucp.incorrect_count, 0) as incorrect_count,
             COALESCE(ucp.confidence_level, 0.5) as confidence_level,
             COALESCE(ucp.next_review_date, NOW()) as next_review_date
      FROM cards c
      LEFT JOIN user_card_progress ucp ON c.id = ucp.card_id AND ucp.user_id = $1
      WHERE c.subject_id = $2
      AND (ucp.next_review_date IS NULL OR ucp.next_review_date <= NOW())
      ORDER BY COALESCE(ucp.next_review_date, c.created_at) ASC
      LIMIT $3
    `, [req.user.id, subjectId, limit]);

    res.json({ cards: result.rows });
  } catch (error) {
    console.error('Get study cards error:', error);
    res.status(500).json({ error: 'Failed to get study cards' });
  }
});

// Admin routes

// Get all users (admin only)
app.get('/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.email, u.auth_type, u.daily_card_limit,
        u.cards_generated_today, u.api_calls_today, u.last_reset_date, u.created_at,
        COUNT(DISTINCT s.id) as subject_count,
        COUNT(DISTINCT c.id) as total_cards,
        COUNT(DISTINCT ucp.id) as cards_studied
      FROM users u
      LEFT JOIN subjects s ON u.id = s.user_id
      LEFT JOIN cards c ON s.id = c.subject_id
      LEFT JOIN user_card_progress ucp ON u.id = ucp.user_id
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `);

    res.json({ users: result.rows });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// Update user auth level (admin only)
app.put('/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { authType, dailyCardLimit } = req.body;

    if (!authType || !['guest', 'friend', 'premium', 'admin'].includes(authType)) {
      return res.status(400).json({ error: 'Invalid auth type' });
    }

    const result = await pool.query(`
      UPDATE users 
      SET auth_type = $1, daily_card_limit = $2
      WHERE id = $3 
      RETURNING id, email, auth_type, daily_card_limit, created_at
    `, [authType, dailyCardLimit || 10, userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ 
      message: 'User updated successfully',
      user: result.rows[0] 
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Get system stats (admin only)
app.get('/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [userStats, cardStats, activityStats] = await Promise.all([
      // User stats
      pool.query(`
        SELECT 
          auth_type,
          COUNT(*) as count
        FROM users 
        GROUP BY auth_type
      `),
      
      // Card stats
      pool.query(`
        SELECT 
          COUNT(DISTINCT s.id) as total_subjects,
          COUNT(DISTINCT c.id) as total_cards,
          COUNT(DISTINCT ucp.id) as total_progress_records
        FROM subjects s
        LEFT JOIN cards c ON s.id = c.subject_id
        LEFT JOIN user_card_progress ucp ON c.id = ucp.card_id
      `),
      
      // Recent activity
      pool.query(`
        SELECT 
          DATE(created_at) as date,
          COUNT(*) as cards_generated
        FROM cards 
        WHERE created_at >= NOW() - INTERVAL '7 days'
        GROUP BY DATE(created_at)
        ORDER BY date DESC
      `)
    ]);

    res.json({
      usersByType: userStats.rows,
      systemStats: cardStats.rows[0],
      recentActivity: activityStats.rows
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// Update card progress after study session
app.post('/cards/:cardId/progress', authenticateToken, async (req, res) => {
  try {
    const { cardId } = req.params;
    const { correct } = req.body;

    // Spaced repetition algorithm - simple version
    const calculateNextReview = (correct, currentConfidence = 0.5) => {
      let newConfidence = correct ? 
        Math.min(1, currentConfidence + 0.1) : 
        Math.max(0, currentConfidence - 0.2);
      
      // Calculate next review interval in hours
      const baseInterval = correct ? 24 : 4; // 1 day vs 4 hours
      const confidenceMultiplier = newConfidence * 2; // 0-2x multiplier
      const intervalHours = Math.floor(baseInterval * confidenceMultiplier);
      
      const nextReview = new Date();
      nextReview.setHours(nextReview.getHours() + Math.max(1, intervalHours));
      
      return { newConfidence, nextReview };
    };

    // Get current progress
    const currentProgress = await pool.query(`
      SELECT * FROM user_card_progress 
      WHERE user_id = $1 AND card_id = $2
    `, [req.user.id, cardId]);

    const { newConfidence, nextReview } = calculateNextReview(
      correct, 
      currentProgress.rows[0]?.confidence_level || 0.5
    );

    // Upsert progress record
    await pool.query(`
      INSERT INTO user_card_progress (
        user_id, card_id, correct_count, incorrect_count, 
        last_seen, next_review_date, confidence_level
      ) VALUES ($1, $2, $3, $4, NOW(), $5, $6)
      ON CONFLICT (user_id, card_id) 
      DO UPDATE SET
        correct_count = user_card_progress.correct_count + $3,
        incorrect_count = user_card_progress.incorrect_count + $4,
        last_seen = NOW(),
        next_review_date = $5,
        confidence_level = $6
    `, [req.user.id, cardId, correct ? 1 : 0, correct ? 0 : 1, nextReview, newConfidence]);

    res.json({ success: true, nextReview, confidence: newConfidence });
  } catch (error) {
    console.error('Update progress error:', error);
    res.status(500).json({ error: 'Failed to update progress' });
  }
});

// Start server with proper database connection
const startServer = async () => {
  try {
    console.log('🚀 Starting Claude Flashcards Backend...');
    
    // Wait for database connection
    const dbConnected = await waitForDatabase();
    if (!dbConnected) {
      console.error('❌ Cannot start server without database connection');
      process.exit(1);
    }
    
    // Run migrations
    await runMigrations();
    
    // Start the server
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 Health check: /health`);
      console.log(`🗄️  Database: connected`);
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('🛑 Shutting down gracefully...');
  if (pool) {
    await pool.end();
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('🛑 Shutting down gracefully...');
  if (pool) {
    await pool.end();
  }
  process.exit(0);
});

// Start everything
startServer();
