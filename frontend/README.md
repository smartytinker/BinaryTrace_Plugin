# BinaryWatch – Frontend

Production-ready report viewer UI for the FastAPI backend in `api.py`.

## Prerequisites

- Node.js 20+ (recommended)
- Backend running locally on `http://127.0.0.1:8000`

## Setup

From this folder:

```bash
npm install
```

Create `.env` (or set an environment variable) with your backend URL:

```bash
copy .env.example .env
```

## Run (dev)

```bash
npm run dev
```

Open the UI at `http://127.0.0.1:5173`.

## Build (prod)

```bash
npm run build
npm run preview
```

## Notes

- The UI calls the backend endpoints:
  - `GET /report/{sha256}`
  - `GET /iocs/{sha256}`
- If you run frontend and backend on different origins, you may need CORS enabled in the backend.

