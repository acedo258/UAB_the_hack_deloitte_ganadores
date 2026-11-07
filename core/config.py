"""Configuración común. Todo se lee de variables de entorno (ver .env.example)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Carpeta del dataset de Deloitte (el repo DTT-UAB-The-Hack clonado). No se sube a nuestro repo.
DATA_DIR = Path(os.getenv("SOC_DATA_DIR", ROOT / "data" / "DTT-UAB-The-Hack")).resolve()
DB_PATH = Path(os.getenv("SOC_DB_PATH", ROOT / "data" / "tarvia.duckdb")).resolve()

# API simulada de Deloitte (solo para contención y aprobaciones)
MOCK_API_URL = os.getenv("MOCK_API_URL", "http://localhost:8000")

# LLM: cualquier endpoint compatible con OpenAI (Ollama, Groq, vLLM...)
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen3-soc")
LLM_API_KEY = os.getenv("LLM_API_KEY", "ollama")
LLM_TIMEOUT_S = float(os.getenv("LLM_TIMEOUT_S", "120"))

# Presupuesto de contexto por alerta (Groq gratis: 8.000 tokens por minuto)
PACK_MAX_CHARS = int(os.getenv("PACK_MAX_CHARS", "16000"))  # ~4.000 tokens

CACHE_DIR = Path(os.getenv("SOC_CACHE_DIR", ROOT / "data" / "cache")).resolve()
