# Raksha backend — containerized so "works on my machine" (and all the
# Tesseract-path/interpreter-mismatch pain from local Windows setup)
# simply doesn't happen for anyone who deploys this. Tesseract-OCR is
# installed at the OS level below, so app/image_processor.py needs NO
# tesseract_cmd override at all when running in this container — it's
# already correctly on PATH.

FROM python:3.12-slim

# Tesseract-OCR (the actual binary, not just the Python wrapper) —
# this is the exact dependency that caused the local Windows setup pain.
# Installing it here means every deployment gets a working OCR path
# automatically, with zero manual steps.
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./app

# Render (and most PaaS free tiers) inject the port to bind via $PORT;
# default to 8000 for local `docker run` testing.
ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
