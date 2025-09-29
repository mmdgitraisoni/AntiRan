mport requests
API_BASE = "http://localhost:8000"
# Start monitoring (replace with your test dirs)
response = requests.post(f"{API_BASE}/start_monitoring", json={"directories": ["/path/to/monitor/dir1", "/path/to/monitor/dir2"]})
print(response.json())
# Check status
print(requests.get(f"{API_BASE}/status").json())
# Get logs
print(requests.get(f"{API_BASE}/logs").json())
# Stop
requests.post(f"{API_BASE}/stop_monitoring")
