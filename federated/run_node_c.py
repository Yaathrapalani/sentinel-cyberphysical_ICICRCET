import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from federated.client import start_client

if __name__ == "__main__":
    # node_c runs as Byzantine malicious node
    # It sends poisoned weights — Krum should reject it
    start_client(
        node_id="node_c",
        server_address="127.0.0.1:8080",
        malicious=True
    )