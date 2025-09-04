# Charlie's Claude Cards - AI-Powered Flashcards

A spaced repetition flashcard app that uses Claude AI to generate study materials on demand.

## Features

- 🧠 **AI-Generated Content**: Claude creates contextually appropriate flashcards based on your prompts
- 🎮 **Gamification**: XP system, levels, streaks, and progress tracking
- 📱 **Mobile-Friendly**: Responsive design that works great on phones
- 🎯 **Smart Difficulty**: Easy/Medium/Hard cards with appropriate XP rewards
- 📊 **Progress Tracking**: Session stats and exportable progress data

## Tech Stack

- **Frontend**: React, Tailwind CSS, Lucide React Icons
- **Backend**: Node.js, Express (deployed on Railway)
- **AI**: Claude 3.5 Sonnet via Anthropic API

## Setup

1. **Clone and install dependencies:**
```bash
git clone https://github.com/yourusername/claude-flashcards-frontend
cd claude-flashcards-frontend
npm install
```

2. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your backend URL
```

3. **Run locally:**
```bash
npm start
```

4. **Get a Claude API key:**
   - Sign up at https://console.anthropic.com
   - Create an API key starting with `sk-ant-`

## Deployment

Deployed on Vercel with automatic GitHub integration. Backend runs on Railway.

## Usage

1. Enter your Claude API key
2. Describe what you want to study (e.g., "French GCSE vocabulary - food and drinks")
3. Generate AI-powered flashcards
4. Study and earn XP as you learn!

## Examples

Try prompts like:
- "Spanish irregular verbs in past tense"
- "German numbers 1-100 with pronunciation"
- "Japanese hiragana characters"
- "Chemistry periodic table first 20 elements"
