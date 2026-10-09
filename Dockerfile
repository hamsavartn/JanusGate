# AgentSentinel — container image
FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY simulator/ simulator/
COPY evals/ evals/
COPY dashboard/ dashboard/
COPY .streamlit/ .streamlit/

# Audit log lives on a writable volume
RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 8123 8501

# Default: API. Override for dashboard:
#   docker run agentsentinel streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8123"]
