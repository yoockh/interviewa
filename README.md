# AI-Powered Adaptive Mock Interview – Flow

## Step 1: User Registration & Profiling
User registers via:
- Email or OAuth

User completes a detailed profile:
- Resume / CV upload (PDF)
  - Parsed into structured data
- Education and work experience
- Tech stack and target role
- Self-assessment (technical & soft skills)
- Interview preferences (difficulty, style)

Profile data is stored in the database and transformed into embeddings for AI context.

**Result:**  
The AI understands the user’s background before the interview starts.

---

## Step 2: Session Initialization
- User clicks **Start Mock Interview**
- System loads:
  - User profile
  - Interview history (if available)
- Gemini (via Vertex AI) generates the first interview question based on:
  - Target role
  - Experience level
- Question is displayed as text
- Optional: Question is converted to voice using Text-to-Speech (TTS)

---

## Step 3: User Response
- User answers using voice
- Speech-to-Text (STT) converts audio into text
- Text is sent to the Vertex AI pipeline
- Gemini:
  - Evaluates the answer
  - Stores logs and scores in the database
- Adaptive behavior:
  - Follow-up questions are generated based on the user’s response

---

## Step 4: Analysis & Feedback
After the interview session:
- Gemini generates structured feedback:
  - Technical accuracy
  - Soft skill evaluation
  - Communication clarity
- Feedback is delivered as:
  - Text (dashboard)
  - Optional voice output (TTS)
- All feedback is saved as interview history

---

## Step 5: Progress Tracking
- System aggregates interview logs and scores
- Dashboard visualizes:
  - Skill improvement across sessions
  - Weak areas and improvement trends
  - Recommended focus areas
- User can update profile data and repeat interviews

**Result:**  
Users can track their improvement over time with measurable insights.

---

## Step 6: Optional Expansion (Future Work)
- Non-verbal analysis (camera):
  - Body language
  - Speaking pace and tone
- Personalized learning or practice recommendations
- Role-specific interview simulations

---

## Flow Summary
Register → Complete Profile → Start Session → AI Questions  
→ User Answers → AI Evaluation → Feedback & Logs  
→ Progress Tracking → Repeat
