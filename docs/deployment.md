# Deployment guide

Three options, cheapest first. The system runs with zero API keys; adding `GEMINI_API_KEY`
enables the LLM judge + embedding layers (env var / platform secret).

## Option A — Docker anywhere (Railway / Render / Fly.io / a VPS)

```bash
docker build -t agentsentinel .
docker run -p 8123:8123 -e GEMINI_API_KEY=... agentsentinel          # API
docker run -p 8501:8501 agentsentinel \
  streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0   # dashboard
```

- **Railway:** new project → Deploy from Dockerfile → set `GEMINI_API_KEY` secret → done.
- **Render:** new Web Service → "Deploy an existing image" or Dockerfile → same.

## Option B — Hugging Face Spaces (free, no Docker account needed)

1. Create a Space → SDK: Docker.
2. Push this repo; set the Space's `app_port` to 8123.
3. Add `GEMINI_API_KEY` under Space → Settings → Secrets.
4. For the dashboard, a second Space with CMD override to Streamlit works.

## Option C — Local/LAN demo (no cloud at all)

The README quickstart IS the deployment: backend on :8123, dashboard on :8501. For the demo
video, localhost is fine; for judges, prefer Option A/B for a click-able link.

## Post-deploy checklist

- [ ] `GET /health` returns `{"status": "ok"}` on the public URL
- [ ] Dashboard "Backend URL" field pointed at the public URL
- [ ] Run the Attack suite on the deployed instance (screenshot for Devpost)
- [ ] Note the URL in `docs/devpost.md` and README

## Security note for deployment

Never put `GEMINI_API_KEY` in code or the repo — platform secrets only. The audit log volume
(`/app/data`) contains inspected text; treat it as sensitive and don't expose it publicly
(there is no auth by design — see docs/constraints.md §6, accepted cuts).
