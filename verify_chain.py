"""Quick SHA256 chain integrity verification."""
import json
import hashlib

def verify():
    with open("logs/detection_logs_20260505_083516.json", "r", encoding="utf-8") as f:
        logs = json.load(f)
    
    print(f"Total detection entries: {len(logs)}")
    print(f"Entry keys: {list(logs[0].keys())}")
    
    # Verify SHA256 chain
    prev = "0" * 64
    chain_ok = True
    for i, entry in enumerate(logs):
        if entry.get("prev_hash") != prev:
            print(f"  CHAIN BREAK at entry {i}: expected={prev[:16]}... got={entry['prev_hash'][:16]}...")
            chain_ok = False
            break
        # Recompute hash
        check_entry = {k: v for k, v in entry.items() if k != "sha256"}
        raw = json.dumps(check_entry, sort_keys=True, default=str).encode("utf-8")
        computed = hashlib.sha256(raw).hexdigest()
        if computed != entry["sha256"]:
            print(f"  HASH MISMATCH at entry {i}")
            chain_ok = False
            break
        prev = entry["sha256"]
    
    if chain_ok:
        print("SHA256 chain: VERIFIED INTACT")
    
    # Sample entries
    for i in [0, len(logs)//2, -1]:
        e = logs[i]
        print(f"\n  Entry [{i}]: node={e['node_id']} type={e['attack_type']} sev={e['severity']} state={e['system_state']}")
        print(f"    sha256={e['sha256'][:32]}...")

verify()
