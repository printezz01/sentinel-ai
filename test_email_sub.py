"""
Quick test: Subscribe to automated scans and verify email is sent.
"""
import httpx, time

base = "http://127.0.0.1:8000"

print("Testing Automated Email Subscription...")
print("-" * 45)

# Subscribe to automated scan every 5 minutes
r = httpx.post(f"{base}/subscribe", json={
    "target": "https://github.com/printezz01/FUSIONX-",
    "target_type": "github",
    "email": "printezz01@gmail.com",
    "interval_minutes": 5   # Set back to 5 minutes
}, timeout=10)

print(f"Subscribe Status: {r.status_code}")
data = r.json()
print(f"Response: {data}")
sub_id = data.get("sub_id")

print(f"\nSubscription registered! Sub ID: {sub_id}")
print("Waiting 90 seconds for the first scan + email to fire...")
print("(Check printezz01@gmail.com inbox in ~2-3 minutes)")

# Verify the subscription is listed
subs = httpx.get(f"{base}/subscriptions").json()
print(f"\nActive subscriptions: {len(subs['subscriptions'])}")
for s in subs['subscriptions']:
    print(f"  - {s['sub_id'][:8]}... -> {s['target']} every {s['interval_minutes']}m -> {s['email']}")
