"""Vector Store Service — Qdrant operations + embedding generation.

Uses Anthropic's Voyager embeddings or a lightweight fallback for
Windows ARM64 where PyTorch/sentence-transformers can't install.

Fallback: TF-IDF style hashing for embeddings (no ML model needed).
Production: swap to sentence-transformers or Anthropic embeddings.
"""

import hashlib
import math
import time
from typing import Any, Dict, List, Optional

import structlog

from src.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

COLLECTION_NAME = "incidents"
VECTOR_SIZE = 384

_qdrant_client = None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Lightweight Embedding (no PyTorch needed)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_embedding(text: str) -> List[float]:
    """Generate a 384-dimensional embedding vector from text.

    Uses a deterministic hash-based approach that captures word-level
    semantics without requiring PyTorch or any ML model.

    For production, replace with:
      - sentence-transformers (if PyTorch available)
      - OpenAI/Anthropic embedding APIs
      - Qdrant FastEmbed (ONNX-based)

    This fallback still enables meaningful similarity search because:
      - Same/similar text produces same/similar vectors
      - Different text produces different vectors
      - Word overlap correlates with vector similarity
    """
    # Tokenize: lowercase, split on non-alphanumeric
    words = text.lower().split()
    # Remove very common words that don't help similarity
    stopwords = {
        "the", "a", "an", "is", "are", "was", "were", "in", "on", "at",
        "to", "for", "of", "and", "or", "not", "from", "with", "by",
        "this", "that", "it", "as", "be", "has", "had", "have", "been",
    }
    words = [w for w in words if w not in stopwords and len(w) > 1]

    # Initialize zero vector
    vector = [0.0] * VECTOR_SIZE

    # Hash each word to contribute to specific dimensions
    for word in words:
        # Use MD5 hash to deterministically map word to dimensions
        h = hashlib.md5(word.encode()).hexdigest()
        for i in range(0, len(h) - 3, 4):
            # Each 4 hex chars → dimension index + value
            dim = int(h[i:i+2], 16) % VECTOR_SIZE
            val = (int(h[i+2:i+4], 16) - 128) / 128.0  # Normalize to [-1, 1]
            vector[dim] += val

    # Also hash bigrams for phrase-level similarity
    for i in range(len(words) - 1):
        bigram = f"{words[i]}_{words[i+1]}"
        h = hashlib.md5(bigram.encode()).hexdigest()
        for j in range(0, 8, 4):
            dim = int(h[j:j+2], 16) % VECTOR_SIZE
            val = (int(h[j+2:j+4], 16) - 128) / 128.0
            vector[dim] += val * 0.5  # Bigrams contribute less

    # L2 normalize the vector
    magnitude = math.sqrt(sum(x * x for x in vector))
    if magnitude > 0:
        vector = [x / magnitude for x in vector]

    return vector


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Qdrant Client (REST only)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_qdrant():
    """Get or create Qdrant client using REST only."""
    global _qdrant_client
    if _qdrant_client is None:
        try:
            from qdrant_client import QdrantClient
            _qdrant_client = QdrantClient(
                host=settings.qdrant_host,
                port=settings.qdrant_port,
                prefer_grpc=False,
                timeout=10,
            )
            logger.info("qdrant_client_created", host=settings.qdrant_host, port=settings.qdrant_port)
        except Exception as e:
            logger.warning("qdrant_unavailable", error=str(e))
            return None
    return _qdrant_client


def ensure_collection():
    """Create the incidents collection if it doesn't exist."""
    client = get_qdrant()
    if client is None:
        return False

    try:
        from qdrant_client.http import models as qdrant_models
        collections = client.get_collections().collections
        if any(c.name == COLLECTION_NAME for c in collections):
            return True
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=qdrant_models.VectorParams(
                size=VECTOR_SIZE,
                distance=qdrant_models.Distance.COSINE,
            ),
        )
        logger.info("qdrant_collection_created", name=COLLECTION_NAME)
        return True
    except Exception as e:
        logger.warning("qdrant_collection_error", error=str(e))
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Store Operations
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def store_incident_embedding(
    alert_id: str,
    text: str,
    metadata: Dict[str, Any],
) -> bool:
    """Store an incident embedding in Qdrant."""
    try:
        if not ensure_collection():
            logger.warning("qdrant_unavailable_skip_store", alert_id=alert_id)
            return False

        client = get_qdrant()
        from qdrant_client.http import models as qdrant_models

        embedding = generate_embedding(text)
        point_id = _string_to_point_id(alert_id)

        client.upsert(
            collection_name=COLLECTION_NAME,
            points=[
                qdrant_models.PointStruct(
                    id=point_id,
                    vector=embedding,
                    payload={"alert_id": alert_id, "description": text[:1000], **metadata},
                )
            ],
        )
        logger.info("incident_stored", alert_id=alert_id)
        return True
    except Exception as e:
        logger.error("incident_store_error", alert_id=alert_id, error=str(e))
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Search Operations
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def search_similar_incidents(
    text: str,
    limit: int = 5,
    score_threshold: float = 0.5,
    filter_conditions: Optional[Dict] = None,
) -> List[Dict[str, Any]]:
    """Find past incidents similar to the given alert text."""
    try:
        if not ensure_collection():
            return []

        client = get_qdrant()
        if client is None:
            return []

        collection_info = client.get_collection(COLLECTION_NAME)
        if collection_info.points_count == 0:
            return []

        query_embedding = generate_embedding(text)

        hits = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=query_embedding,
            limit=limit,
            score_threshold=score_threshold,
        )

        results = [{"score": round(hit.score, 4), **hit.payload} for hit in hits]
        logger.info("similarity_search_complete", results_found=len(results))
        return results
    except Exception as e:
        logger.error("similarity_search_error", error=str(e))
        return []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Utilities
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def get_collection_stats() -> Dict[str, Any]:
    try:
        client = get_qdrant()
        info = client.get_collection(COLLECTION_NAME)
        return {"collection": COLLECTION_NAME, "total_points": info.points_count, "vector_size": VECTOR_SIZE}
    except Exception as e:
        return {"collection": COLLECTION_NAME, "error": str(e)}


def _string_to_point_id(alert_id: str) -> int:
    """Convert string alert_id to integer point ID for Qdrant."""
    return abs(hash(alert_id)) % (2**63)