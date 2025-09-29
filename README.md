# AntiRan

This system focuses on real-time file monitoring to detect potential ransomware behavior (e.g., rapid file encryption, unusual file modifications, or entropy spikes in files). It includes:

File Monitoring System: Uses Python's watchdog library to monitor directories for file changes.
Detection Engine: A rule-based engine (with optional hooks for ML-based anomaly detection) that analyzes file events for ransomware signatures, such as high-volume encryptions or file renaming patterns.
Backend with REST API: Built using FastAPI (a modern, fast Python framework) to expose endpoints for starting/stopping monitoring, querying detection logs, and receiving alerts.

High-Level Architecture
File Monitor: Watches specified directories for events (create, modify, delete, move).
Detection Engine: Processes events in real-time. Flags suspicious activity based on rules (e.g., >10 files modified in 1 minute, file extensions changing to .encrypted, or entropy analysis).
REST API Backend: Handles configuration, logs, and alerts. Runs as a server that the monitor and engine can interact with.
Data Flow:
Monitor detects changes → Sends to Engine.
Engine analyzes → Logs/alerts via API.
API endpoints allow external control (e.g., via a web dashboard or SIEM integration).
