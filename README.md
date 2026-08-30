# RAKSHA-AI_SCAM_DETECTOR

A multi-modal scam detection platform: paste text/URLs or upload screenshots
and QR codes, and get an instant risk score, verdict, and plain-language
explanation from "Sentinel" — before you click a link, scan a QR, or send
money.

All 4 build steps are complete:
- ✅ Step 1: FastAPI core + rule scorer + SQLite threat graph
- ✅ Step 2: OCR (screenshots) + QR code decoding + transaction-QR scoring
- ✅ Step 3: Local LLM (Ollama) narration layer
- ✅ Step 4: Frontend (Sentinel UI)

## Quick start (run both pieces)

**1. Backend** (see `backend/README.md` for full setup incl. Tesseract/Ollama):
```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m app.seed_data         # only needed once
uvicorn app.main:app --reload --port 8000
```
Leave this running. Confirm it's up at `http://127.0.0.1:8000/docs`.

**2. Frontend:**
Just open `frontend/index.html` directly in your browser (double-click it,
or right-click → Open With → your browser). No build step, no server needed
— it's a single static file that talks to the backend on `localhost:8000`.

> If you get a CORS or "can't reach backend" error in the browser console,
> make sure the backend is running FIRST, and that you're hitting it on
> port 8000 (the frontend is hardcoded to `http://127.0.0.1:8000` — change
> `API_BASE` at the top of the `<script>` in `index.html` if you run the
> backend on a different port).

## What the frontend does
- **Sentinel** — the glowing orb character — reacts to results: calm teal
  breathing when idle/safe, escalating to amber/red pulsing with a shake
  for suspicious/dangerous verdicts
- Three input modes: paste text/URL, drag-and-drop a screenshot, or a QR
  code image — each hits a different backend endpoint
  (`/analyze`, `/analyze/screenshot`, `/analyze/qr`)
- Radar-sweep animation while scanning, radial gauge + typewriter
  explanation on result
- Entity chips show prior report counts from the threat graph (the "14
  people reported this number" moment — your strongest demo beat)
- "Report as scam" button wired to `/report`, feeding the threat graph

## For the hackathon demo
Good demo order: (1) paste the seeded scam message from
`backend/app/seed_data.py` first — shows a dramatic 100/dangerous score
with multiple threat-graph hits immediately. (2) Then paste something
benign to show it correctly scores low. (3) Then show a screenshot or QR
upload to demonstrate multi-modal input. Keep Ollama warmed up (run one
throwaway `/analyze` call right before you go on stage) so the LLM
explanation doesn't hit the cold-start delay we ran into during dev.
