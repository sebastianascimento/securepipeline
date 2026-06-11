FROM python:3.11-slim

WORKDIR /app

# Instala dependências do sistema para WeasyPrint
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copia e instala dependências Python
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código
COPY src/ .

# Utilizador não-root — boa prática que o teu próprio scanner detetaria
RUN useradd -m appuser
USER appuser

ENTRYPOINT ["python", "cli.py"]