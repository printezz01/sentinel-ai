import httpx

base = "http://127.0.0.1:8000"
scan_id = "1e06e35b-2f00-4fc0-af20-ab511f1f6219" # New FUSIONX scan with embeddings

print("Testing Voyage AI Semantic RAG Chat")
print("-" * 40)

# Question that needs semantic understanding, not just keyword matching
q = "What findings show credentials that could be used by an attacker?"
print(f"Question: {q}")

r = httpx.post(
    f"{base}/scan/{scan_id}/chat",
    json={"question": q},
    timeout=30
)
data = r.json()

print(f"\nResponse (HTTP {r.status_code}):")
print(data.get("answer", ""))

print("\nContext findings matched:")
for c in data.get("context", []):
    print(f" - [{c.get('severity')}] {c.get('title')}")
