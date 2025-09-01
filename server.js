const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Claude Flashcards Backend is running!',
    timestamp: new Date().toISOString()
  });
});

// Generate flashcards endpoint
app.post('/generate-cards', async (req, res) => {
  try {
    const { prompt, apiKey } = req.body;

    if (!apiKey || !apiKey.startsWith('sk-ant-')) {
      return res.status(400).json({ 
        error: 'Invalid API key. Must start with sk-ant-' 
      });
    }

    if (!prompt) {
      return res.status(400).json({ 
        error: 'Prompt is required' 
      });
    }

    console.log('🚀 Generating flashcards for:', prompt);

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-3-5-sonnet-20241022',
        max_tokens: 2000,
        messages: [{
          role: 'user',
          content: `Generate 25 flashcards for: "${prompt}"

Format as JSON array with this exact structure:
[
  {
    "front": "Question or term to translate",
    "back": "Answer or translation", 
    "difficulty": "easy|medium|hard",
    "category": "category name"
  }
]

Make the flashcards appropriate for the level and varied in difficulty. Only return the JSON array, no other text.`
        }]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ Claude API Error:', response.status, errorText);
      
      if (response.status === 401) {
        return res.status(401).json({ error: 'Invalid Claude API key' });
      } else if (response.status === 429) {
        return res.status(429).json({ error: 'Rate limit exceeded. Please wait and try again.' });
      } else {
        return res.status(response.status).json({ 
          error: `Claude API error: ${response.status} ${errorText}` 
        });
      }
    }

    const data = await response.json();
    const content = data.content[0].text;
    
    // Extract JSON from Claude's response
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      const cards = JSON.parse(jsonMatch[0]);
      console.log('✅ Generated', cards.length, 'flashcards');
      res.json({ flashcards: cards });
    } else {
      console.error('❌ Could not parse JSON from:', content);
      res.status(500).json({ 
        error: 'Could not parse flashcards from Claude response',
        rawResponse: content 
      });
    }

  } catch (error) {
    console.error('🔥 Server error:', error);
    res.status(500).json({ 
      error: 'Internal server error: ' + error.message 
    });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
