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
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY; // Your Claude API key

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

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
    timestamp: new Date().toISOString()
  });
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

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
