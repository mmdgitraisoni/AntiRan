from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import uvicorn
import os
import time
import logging
from typing import List, Dict, Optional
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import numpy as np
import psutil  # For process monitoring
from sklearn.cluster import KMeans  # Simple ML for anomaly clustering
from datetime import datetime
import yaml
from database import load_config, engine, get_db, add_alert, get_all_alerts
from models import DetectionAlert as DBAlert
from io import StringIO
import csv

app = FastAPI(title="Enhanced Ransomware Detection Tool")

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()
config = load_config()
API_KEY = config['api']['api_key']

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials

# Global state
monitoring_active = False
observer: Observer = None
monitored_dirs: List[str] = config['monitoring']['directories']
engine_instance = None  # Detection engine instance

class DetectionAlert(BaseModel):
    timestamp: str
    file_path: str
    event_type: str
    suspicion_level: str
    reason: str
    entropy: Optional[float] = None

class MonitorConfig(BaseModel):
    directories: Optional[List[str]] = None

# Enhanced Detection Engine
class DetectionEngine:
    def __init__(self, config: dict):
        self.recent_events = []
        self.event_window = config['monitoring']['event_window']
        self.high_volume_threshold = config['monitoring']['high_volume_threshold']
        self.entropy_threshold = config['detection']['entropy_threshold']
        self.suspicious_extensions = config['detection']['suspicious_extensions']
        self.max_file_size_anomaly = config['detection']['max_file_size_anomaly'] * 1024  # bytes
        self.file_sizes = {}  # Track file sizes over time
        self.ml_model = KMeans(n_clusters=2, random_state=42)  # Simple anomaly clustering
        self.historical_entropies = []  # For ML training

    def analyze_event(self, event, db) -> Optional[DetectionAlert]:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_path = event.src_path if hasattr(event, 'src_path') else getattr(event, 'dest_path', '')
        event_type = event.event_type

        # Track recent events
        self.recent_events.append((time.time(), event_type, file_path))
        self._cleanup_old_events()

        alert_data = {
            'timestamp': timestamp,
            'file_path': file_path,
            'event_type': event_type,
            'suspicion_level': 'low',
            'reason': '',
            'entropy': None
        }

        # Rule 1: High-volume modifications
        recent_count = len([e for e in self.recent_events if e[0] > time.time() - self.event_window])
        if recent_count > self.high_volume_threshold:
            alert_data['suspicion_level'] = 'high'
            alert_data['reason'] = f"High-volume activity ({recent_count} events in {self.event_window}s)"
            self._log_and_store(db, alert_data)
            return DetectionAlert(**alert_data)

        # Rule 2: Suspicious extensions
        if any(ext in file_path.lower() for ext in self.suspicious_extensions):
            alert_data['suspicion_level'] = 'high'
            alert_data['reason'] = "Suspicious file extension detected"
            self._log_and_store(db, alert_data)
            return DetectionAlert(**alert_data)

        # Rule 3: File size anomaly (rapid growth)
        if event_type == 'modified' and os.path.exists(file_path):
            current_size = os.path.getsize(file_path)
            prev_size = self.file_sizes.get(file_path, 0)
            if current_size - prev_size > self.max_file_size_anomaly:
                alert_data['suspicion_level'] = 'medium'
                alert_data['reason'] = f"Rapid file size increase ({current_size - prev_size} bytes)"
                self.file_sizes[file_path] = current_size
                self._log_and_store(db, alert_data)
                return DetectionAlert(**alert_data)

        # Rule 4: Entropy analysis with ML anomaly detection
        if event_type == 'modified' and os.path.exists(file_path):
            entropy = self._calculate_entropy(file_path)
            alert_data['entropy'] = entropy
            if entropy > self.entropy_threshold:
                # Simple ML: Cluster entropies; flag if outlier
                if self.historical_entropies:
                    self.historical_entropies.append(entropy)
                    if len(self.historical_entropies) > 10:  # Retrain periodically
                        self.ml_model.fit(np.array(self.historical_entropies).reshape(-1, 1))
                        cluster = self.ml_model.predict([[entropy]])[0]
                        if cluster == 1:  # Assume cluster 1 is anomalous (high entropy)
                            alert_data['suspicion_level'] = 'high'
                            alert_data['reason'] = f"ML-detected entropy anomaly ({entropy:.2f})"
                            self._log_and_store(db, alert_data)
                            return DetectionAlert(**alert_data)
                else:
                    alert_data['suspicion_level'] = 'medium'
                    alert_data['reason'] = f"High entropy ({entropy:.2f}) - possible encryption"
                    self._log_and_store(db, alert_data)
                    return DetectionAlert(**alert_data)

        # Rule 5: Basic process monitoring (e.g., suspicious processes accessing files)
        if event_type in ['modified', 'created']:
            suspicious_procs = self._check_suspicious_processes(file_path)
            if suspicious_procs:
                alert_data['suspicion_level'] = 'medium'
                alert_data['reason'] = f"Suspicious process accessing file: {suspicious_procs}"
                self._log_and_store(db, alert_data)
                return DetectionAlert(**alert_data)

        return None

    def _log_and_store(self, db, alert_data: dict):
        add_alert(db, alert_data)
        logger.warning(f"ALERT: {alert_data['reason']} - {alert_data['file_path']}")

    def _cleanup_old_events(self):
        cutoff = time.time() - self.event_window
        self.recent_events = [e for e in self.recent_events if e[0] > cutoff]

    def _calculate_entropy(self, file_path: str, block_size: int = 1024) -> float:
        try:
            with open(file_path, 'rb') as f:
                data = f.read(block_size)
                if not data:
                    return 0.0
                _, counts = np.unique(data, return_counts=True)
                probs = counts / len(data)
                entropy = -np.sum(probs * np.log2(probs + 1e-10))  # Avoid log(0)
                self.historical_entropies.append(entropy)
                return entropy
        except Exception as e:
            logger.error(f"Entropy calc error: {e}")
            return 0.0

    def _check_suspicious_processes(self, file_path: str) -> List[str]:
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if file_path in ' '.join(proc.info['cmdline'] or []):
                    name = proc.info['name']
                    if 'ransom' in name.lower() or 'crypto' in name.lower():  # Basic rule
                        suspicious.append(name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return suspicious

# Initialize engine
engine_instance = DetectionEngine(config)

# File Monitor Handler
class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, db):
        self.db = db

    def on_any_event(self, event):
        if not event.is_directory:
            alert = engine_instance.analyze_event(event, self.db)
            if alert:
                logger.info(f"Processed alert: {alert}")

# API Endpoints (all require API key via Authorization header)
@app.post("/start_monitoring", response_model=Dict)
def start_monitoring(config_req: MonitorConfig, background_tasks: BackgroundTasks, creds: HTTPAuthorizationCredentials = Depends(verify_api_key), db=Depends(get_db)):
    global monitoring_active, observer, monitored_dirs
    if monitoring_active:
        return {"status": "already_running"}
    
    monitored_dirs = config_req.directories or monitored_dirs
    event_handler = RansomwareHandler(db)
    observer = Observer()
    for directory in monitored_dirs:
        if os.path.exists(directory):
            observer.schedule(event_handler, directory, recursive=config['monitoring']['recursive'])
        else:
            raise HTTPException(status_code=400, detail=f"Directory {directory} does not exist")
    
    observer.start()
    monitoring_active = True
    background_tasks.add_task(observer.join)
    return {"status": "monitoring_started", "directories": monitored_dirs}

@app.post("/stop_monitoring")
def stop_monitoring(creds: HTTPAuthorizationCredentials = Depends(verify_api_key)):
    global monitoring_active, observer
    if monitoring_active:
        observer.stop()
        observer.join()
        monitoring_active = False
    return {"status": "monitoring_stopped"}

@app.get("/logs", response_model=List[DetectionAlert])
def get_logs(limit: int = Query(100, ge=1), db=Depends(get_db), creds: HTTPAuthorizationCredentials = Depends(verify_api_key)):
    alerts = get_all_alerts(db)[:limit]
    return [DetectionAlert(
        timestamp=a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        file_path=a.file_path,
        event_type=a.event_type,
        suspicion_level=a.suspicion_level,
        reason=a.reason,
        entropy=float(a.entropy) if a.entropy else None
    ) for a in alerts]

@app.delete("/logs")
def clear_logs(db=Depends(get_db), creds: HTTPAuthorizationCredentials = Depends(verify_api_key)):
    db.query(DBAlert).delete()
    db.commit()
    return {"status": "logs_cleared"}

@app.get("/logs/export/csv")
def export_logs_csv(db=Depends(get_db), creds: HTTPAuthorizationCredentials = Depends(verify_api_key)):
    alerts = get_all_alerts(db)
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=['timestamp', 'file_path', 'event_type', 'suspicion_level', 'reason', 'entropy'])
    writer.writeheader()
    for a in alerts:
        writer.writerow({
            'timestamp': a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'file_path': a.file_path,
            'event_type': a.event_type,
            'suspicion_level': a.suspicion_level,
            'reason': a.reason,
            'entropy': a.entropy or ''
        })
    return {"csv_data": output.getvalue()}  # In production, return as file response

@app.get("/status")
def get_status(creds: HTTPAuthorizationCredentials = Depends(verify_api_key), db=Depends(get_db)):
    total_alerts = db.query(DBAlert).count()
    return {
        "monitoring_active": monitoring_active,
        "monitored_dirs": monitored_dirs,
        "total_alerts": total_alerts
    }

if __name__ == "__main__":
    uvicorn.run(app, host=config['api']['host'], port=config['api']['port'])
