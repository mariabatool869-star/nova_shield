import threading
import secrets
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import sys
import os

NOVASHIELD_OFFLINE_ONLY = os.environ.get("NOVASHIELD_OFFLINE_ONLY") == "1"
import json
import glob
import re
import time
from collections import defaultdict, deque
from functools import wraps

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, jsonify, request, session
from phase7_soc.case_registry import SocCaseRegistry
from flask_socketio import SocketIO, emit
from minions.optic import Optic
from minions.cortex import Cortex
from minions.vault import Vault
from minions.servo import Servo
from minions.siem import SIEMExporter

app = Flask(__name__)
app.config['NOVASHIELD_OFFLINE_ONLY'] = NOVASHIELD_OFFLINE_ONLY


# SEC-012: Single-process login rate limiting.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 900
login_attempts = defaultdict(deque)
login_attempts_lock = threading.RLock()


def login_client_key():
    # Do not trust forwarded headers without trusted-proxy configuration.
    return request.remote_addr or "unknown"



# SEC-012.10: Remove expired failure records without evicting active lockouts.
LOGIN_CLEANUP_INTERVAL = 60
login_last_cleanup = 0.0


def cleanup_expired_login_attempts(now=None):
    global login_last_cleanup
    with login_attempts_lock:
        now = time.monotonic() if now is None else now

        if now - login_last_cleanup < LOGIN_CLEANUP_INTERVAL:
            return

        for key, attempts in list(login_attempts.items()):
            while attempts and now - attempts[0] >= LOGIN_LOCKOUT_SECONDS:
                attempts.popleft()

            if not attempts:
                login_attempts.pop(key, None)

        login_last_cleanup = now


def login_is_locked(key, now=None):
    with login_attempts_lock:
        now = time.monotonic() if now is None else now
        attempts = login_attempts.get(key)

        if not attempts:
            return False

        while attempts and now - attempts[0] >= LOGIN_LOCKOUT_SECONDS:
            attempts.popleft()

        if not attempts:
            login_attempts.pop(key, None)
            return False

        return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_login_failure(key, now=None):
    with login_attempts_lock:
        now = time.monotonic() if now is None else now
        attempts = login_attempts[key]

        while attempts and now - attempts[0] >= LOGIN_LOCKOUT_SECONDS:
            attempts.popleft()

        attempts.append(now)


def clear_login_failures(key):
    with login_attempts_lock:
        login_attempts.pop(key, None)

from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

flask_secret = os.environ.get("FLASK_SECRET_KEY")
if not flask_secret or len(flask_secret) < 32:
    raise RuntimeError("FLASK_SECRET_KEY is missing or too short")

app.secret_key = flask_secret

# Session cookie security.
# Set NOVASHIELD_HTTPS=true only when serving the dashboard over HTTPS.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("NOVASHIELD_HTTPS", "").lower()
        in ("1", "true", "yes")
    ),
)
socketio = SocketIO(app, async_mode="threading")

# SEC-012.78: Single-process administrator socket authorization.
socket_auth_lock = threading.RLock()
SOCKET_SESSION_LIFETIME = 8 * 60 * 60
SOCKET_SESSION_CLEANUP_INTERVAL = 60
active_socket_sessions = {}
session_sockets = {}
socket_sessions = {}


def revoke_socket_token(token):
    """Revoke a token and disconnect associated sockets."""
    with socket_auth_lock:
        active_socket_sessions.pop(token, None)
        sids = tuple(session_sockets.pop(token, ()))
        for sid in sids:
            socket_sessions.pop(sid, None)
            socketio.server.disconnect(sid, namespace="/")


def cleanup_expired_socket_sessions(now=None):
    """Remove expired administrator sessions and sockets."""
    now = time.monotonic() if now is None else now
    with socket_auth_lock:
        expired = [
            token
            for token, deadline in active_socket_sessions.items()
            if now >= deadline
        ]
        for token in expired:
            revoke_socket_token(token)
    return len(expired)


socket_cleanup_stop_event = threading.Event()
socket_cleanup_lifecycle_lock = threading.RLock()
socket_cleanup_worker_task = None
socket_cleanup_stopping = False
socket_cleanup_generation = 0


def socket_session_cleanup_worker():
    """Periodically revoke expired sessions until stopped."""
    while not socket_cleanup_stop_event.wait(
        SOCKET_SESSION_CLEANUP_INTERVAL
    ):
        cleanup_expired_socket_sessions()


def start_socket_cleanup_worker():
    """Start at most one cleanup worker in this process."""
    global socket_cleanup_worker_task
    global socket_cleanup_generation

    with socket_cleanup_lifecycle_lock:
        if socket_cleanup_stopping:
            return False

        if (
            socket_cleanup_worker_task is not None
            and socket_cleanup_worker_task.is_alive()
        ):
            return False

        socket_cleanup_stop_event.clear()

        try:
            task = socketio.start_background_task(
                socket_session_cleanup_worker
            )
        except Exception:
            socket_cleanup_stop_event.set()
            raise

        socket_cleanup_worker_task = task
        socket_cleanup_generation += 1
        return True


def stop_socket_cleanup_worker(timeout=5.0):
    """Request shutdown and guard against stale finalization."""
    global socket_cleanup_stopping

    with socket_cleanup_lifecycle_lock:
        socket_cleanup_stopping = True
        socket_cleanup_stop_event.set()
        task = socket_cleanup_worker_task
        generation = socket_cleanup_generation

    if task is not None:
        task.join(timeout=timeout)

    with socket_cleanup_lifecycle_lock:
        if (
            socket_cleanup_worker_task is not task
            or socket_cleanup_generation != generation
        ):
            return False

        if task is not None and task.is_alive():
            return False

        socket_cleanup_stopping = False
        return True


def revoke_socket_session():
    """Revoke this browser session and disconnect its sockets."""
    token = session.get("socket_auth_token")
    if not isinstance(token, str):
        return

    revoke_socket_token(token)


def issue_socket_session():
    """Register a new administrator session."""
    token = secrets.token_urlsafe(32)
    with socket_auth_lock:
        active_socket_sessions[token] = (
            time.monotonic() + SOCKET_SESSION_LIFETIME
        )
    session["socket_auth_token"] = token


def is_active_admin_session():
    """Require administrator status and an active server-side token."""
    if session.get("is_admin") is not True:
        return False
    token = session.get("socket_auth_token")
    if not isinstance(token, str):
        return False
    with socket_auth_lock:
        deadline = active_socket_sessions.get(token)
        if deadline is None:
            return False
        if time.monotonic() >= deadline:
            revoke_socket_token(token)
            return False
        return True


# SEC-012: Monitor CSP compatibility without blocking dashboard resources.
@app.after_request
def add_csp_report_only(response):
    response.headers["Content-Security-Policy-Report-Only"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response



if NOVASHIELD_OFFLINE_ONLY:
    optic = cortex = vault = servo = siem = None
else:
    optic = Optic()
    cortex = Cortex()
    vault = Vault()
    servo = Servo()
    siem = SIEMExporter()

from minions.pending_alerts import PendingAlertRegistry

registry = PendingAlertRegistry()

@socketio.on('connect')
def authorize_socket_connection(auth=None):
    if not is_active_admin_session():
        return False
    token = session["socket_auth_token"]
    with socket_auth_lock:
        deadline = active_socket_sessions.get(token)
        if deadline is None or time.monotonic() >= deadline:
            if deadline is not None:
                revoke_socket_token(token)
            return False
        sid = request.sid
        socket_sessions[sid] = token
        session_sockets.setdefault(token, set()).add(sid)


@socketio.on('disconnect')
def cleanup_socket_connection():
    sid = request.sid
    with socket_auth_lock:
        token = socket_sessions.pop(sid, None)
        if token is not None:
            sids = session_sockets.get(token)
            if sids is not None:
                sids.discard(sid)
                if not sids:
                    session_sockets.pop(token, None)

pending_alert = None

# Phase 7C: shared in-memory offline SOC case registry.
soc_case_registry = SocCaseRegistry()

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_active_admin_session():
            return jsonify({"status": "error", "message": "Unauthorized."}), 403
        return f(*args, **kwargs)
    return decorated_function


# SEC-010: Session-bound CSRF token helpers.
def issue_csrf_token():
    """Create a fresh token after successful authentication."""
    import secrets
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def validate_csrf_token():
    """Validate the token supplied by an authenticated browser."""
    import secrets

    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token")

    return (
        is_active_admin_session()
        and isinstance(expected, str)
        and isinstance(supplied, str)
        and secrets.compare_digest(expected, supplied)
    )


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/console-preview')
def console_preview():
    return render_template('index_console_preview.html')



def require_csrf(view):
    """Reject state-changing requests without a valid session token."""
    from functools import wraps

    @wraps(view)
    def protected(*args, **kwargs):
        if not validate_csrf_token():
            return jsonify({
                "status": "error",
                "message": "Invalid or missing CSRF token"
            }), 403

        return view(*args, **kwargs)

    return protected


@app.route('/api/login', methods=['POST'])
def login():
    with login_attempts_lock:
        cleanup_expired_login_attempts()
        client_key = login_client_key()

        if login_is_locked(client_key):
            return jsonify({
                "status": "error",
                "message": "Too many login attempts. Try again later."
            }), 429
        from werkzeug.security import check_password_hash

        data = request.get_json(silent=True)
        revoke_socket_session()
        session.clear()

        if not isinstance(data, dict):
            record_login_failure(client_key)
            return jsonify({
                "status": "error",
                "message": "Invalid credentials"
            }), 401

        password = data.get("password")
        stored_hash = os.environ.get("NOVASHIELD_ADMIN_PASSWORD_HASH")

        if not stored_hash:
            raise RuntimeError(
                "NOVASHIELD_ADMIN_PASSWORD_HASH is not configured"
            )

        if not isinstance(password, str) or not check_password_hash(
            stored_hash, password
        ):
            record_login_failure(client_key)
            return jsonify({
                "status": "error",
                "message": "Invalid credentials"
            }), 401

        clear_login_failures(client_key)
        session["is_admin"] = True
        session["role"] = "admin"
        issue_socket_session()
        issue_csrf_token()

        return jsonify({
            "status": "success",
            "role": "admin"
        })


@app.route('/api/session', methods=['GET'])
def session_status():
    """Report authenticated administrator state without exposing secrets."""
    authenticated = is_active_admin_session()
    csrf_token = session.get("csrf_token") if authenticated else None

    return jsonify({
        "authenticated": authenticated,
        "role": "admin" if authenticated else None,
        "csrf_token": csrf_token
    })


@app.route('/api/logout', methods=['POST'])
@require_csrf
def logout():
    """Clear the current browser session."""
    revoke_socket_session()
    session.clear()

    return jsonify({
        "status": "success",
        "authenticated": False
    })





@app.route('/api/scan', methods=['POST'])
@require_admin
@require_csrf
def scan():
    if NOVASHIELD_OFFLINE_ONLY:
        return jsonify({"status": "disabled", "message": "Unavailable in offline-only mode"}), 503

    global pending_alert
    
    # 🔥 FIX: Accept the log_line from the POST body
    bad_log = "Live TCP: 150 connections from 10.0.0.99 on port 80"
    
    if request.method == 'POST' and request.json:
        bad_log = request.json.get("log_line", bad_log)
    
    print(f"🔍 SCAN RECEIVED: {bad_log}")
    
    alert = optic.scan(bad_log, decision_id=500 + len(glob.glob("records/*.json")))
    if not alert: return jsonify({"status": "clean"})
    
    enriched = cortex.explain(alert)
    enriched = registry.add(enriched)
    
    siem.save_to_file(enriched)
    siem.send_webhook(enriched)
    
    # Only deliver alerts to currently authorized socket sessions.
    # Hold the same lock used for session revocation.
    with socket_auth_lock:
        cleanup_expired_socket_sessions()
        for sid, token in tuple(socket_sessions.items()):
            if token in active_socket_sessions:
                socketio.emit('new_alert', enriched, to=sid)

    
    return jsonify({
        "status": "threat", "alert_id": enriched["alert_id"], "score": enriched["score"],
        "alert_type": enriched.get("alert_type"),
        "explanation": enriched["explanation"], "counterfactual": enriched.get("counterfactual"),
        "raw_log": enriched["raw_log"]
    })

# 🔥 FIX: Add the missing /api/live route
@app.route('/api/live')
@require_admin
def live():
    if NOVASHIELD_OFFLINE_ONLY:
        return jsonify({"status": "disabled", "message": "Unavailable in offline-only mode"}), 503

    alerts = registry.list_pending()
    return jsonify({
        "status": "threat" if alerts else "waiting",
        "alerts": alerts
    })

@app.route('/api/decide', methods=['POST'])
@require_admin
@require_csrf
def decide():
    if NOVASHIELD_OFFLINE_ONLY:
        return jsonify({"status": "disabled", "message": "Unavailable in offline-only mode"}), 503

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    decision = data.get("decision")
    alert_id = data.get("alert_id")

    if decision not in ("approve", "reject"):
        return jsonify({"status": "error", "message": "Invalid decision"}), 400

    if not isinstance(alert_id, str) or not alert_id:
        return jsonify({"status": "error", "message": "Missing alert_id"}), 400

    alert = registry.claim(alert_id)

    if alert is None:
        return jsonify({
            "status": "error",
            "message": "Alert unavailable or already processed"
        }), 409

    try:
        if decision == "reject":
            alert["human_decision"] = "rejected"
            alert["enforcement_status"] = "not_requested"
        else:
            alert["human_decision"] = "approved"
            alert["enforcement_status"] = "not_attempted"

            # Fail closed: enforcement is disabled until separately audited.
            # Never call Servo from this handler without that review.

        alert["analyst"] = "authenticated_admin"
        vault.record(alert, tenant_id="tenant_001")

    except Exception:
        app.logger.exception("Alert decision recording failed")
        # Keep the claim locked rather than risk duplicate enforcement.
        return jsonify({
            "status": "error",
            "message": "Decision recording failed"
        }), 500

    if not registry.complete(alert_id):
        app.logger.error("Could not complete alert claim: %s", alert_id)
        return jsonify({
            "status": "error",
            "message": "Alert state update failed"
        }), 500

    return jsonify({
        "status": "success",
        "alert_id": alert_id,
        "human_decision": alert["human_decision"],
        "enforcement_status": alert["enforcement_status"]
    })

@app.route('/api/verify')
@require_admin
def verify():
    if NOVASHIELD_OFFLINE_ONLY:
        return jsonify({"status": "disabled", "message": "Unavailable in offline-only mode"}), 503

    is_intact, count, report = vault.verify_chain(tenant_id="tenant_001")
    return jsonify({"status": "intact" if is_intact else "compromised", "count": count, "report": report})

@app.route('/api/history')
@require_admin
def history():
    if NOVASHIELD_OFFLINE_ONLY:
        return jsonify({"status": "disabled", "message": "Unavailable in offline-only mode"}), 503

    rows = vault.get_all(tenant_id="tenant_001")
    records = []
    for r in rows:
        records.append({
            "decision_id": r["id"],
            "alert_type": r["alert_type"],
            "score": r["score"],
            "human_decision": r["human_decision"],
            "analyst": r["analyst"],
            "hash": r["hash"],
            "recorded_at": str(r["recorded_at"])
        })
    return jsonify({"records": records})


# PHASE 6 OFFLINE AI PREVIEW
# This endpoint is intentionally read-only and does not register alerts.
@app.route("/api/phase6/offline-predict", methods=["POST"])
@require_admin
@require_csrf
def phase6_offline_predict():
    """Predict one allowlisted offline CIC flow without side effects."""
    import pandas as pd
    import numpy as np
    import sys

    project_root = Path(__file__).resolve().parent.parent
    bridge_src = project_root / "phase6_xai" / "src"
    if str(bridge_src) not in sys.path:
        sys.path.insert(0, str(bridge_src))
    from cortex_phase6_bridge import CortexPhase6Bridge

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"status": "error", "message": "JSON required"}), 400

    row_index = body.get("row_index")
    if type(row_index) is not int or not 0 <= row_index < 20000:
        return jsonify({
            "status": "error",
            "message": "row_index must be an integer from 0 to 19999"
        }), 400

    dataset = (
        project_root / "models" / "datasets" / "cic_2017"
        / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    )

    if not dataset.is_file() or dataset.is_symlink():
        return jsonify({
            "status": "error",
            "message": "Allowlisted CIC dataset unavailable"
        }), 503

    metadata_path = (
        project_root / "phase6_xai" / "artifacts"
        / "model_metadata.json"
    )

    metadata = json.loads(
        metadata_path.read_text(encoding="utf-8")
    )
    required_features = list(metadata["features"])

    try:
        frame = pd.read_csv(
            dataset,
            skiprows=range(1, row_index + 1),
            nrows=1,
            low_memory=False
        )
        frame.columns = frame.columns.str.strip()

        if len(frame) != 1:
            raise ValueError("Requested row unavailable.")

        if not all(name in frame.columns for name in required_features):
            raise ValueError("Dataset features incompatible.")

        values = pd.to_numeric(
            frame.iloc[0][required_features],
            errors="coerce"
        )
        if not np.isfinite(values.to_numpy(dtype=float)).all():
            raise ValueError("Flow contains invalid measurements.")

        alert = {
            "decision_id": "phase6_offline_row_" + str(row_index),
            "features": {
                name: float(values[name])
                for name in required_features
            },
            "action": "monitor",
        }

        # Only this server-side allowlisted dataset path may call
        # the verified-flow entry point.
        bridge = CortexPhase6Bridge()
        enriched = bridge.explain_verified_flow(alert)

        from phase7_soc.soc_report import generate_soc_report
        soc_report = generate_soc_report(enriched)

        if soc_report is not None:
            soc_case_registry.register(soc_report)

    except (ValueError, KeyError, OSError) as exc:
        return jsonify({
            "status": "error",
            "message": str(exc)
        }), 422
    except Exception:
        app.logger.exception("Phase 6 offline inference failed")
        return jsonify({
            "status": "error",
            "message": "Offline inference unavailable"
        }), 503

    return jsonify({
        "status": "success",
        "mode": "offline_cic_ai",
        "row_index": row_index,
        "random_forest": enriched["phase6_ai"]["random_forest"],
        "lightgbm": enriched["phase6_ai"]["lightgbm"],
        "models_agree": enriched["phase6_ai"]["models_agree"],
        "soc_report": soc_report,
        "enforcement_enabled": False,
    })


# PHASE 7C: Human review of registered offline SOC cases.
# No database writes, live alert handling, or enforcement.
@app.route("/api/phase7/soc-decide", methods=["POST"])
@require_admin
@require_csrf
def phase7_soc_decide():
    from phase7_soc.analyst_decisions import validate_analyst_decision

    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        return jsonify({
            "status": "error",
            "message": "JSON object required"
        }), 400

    try:
        decision = validate_analyst_decision(
            case_id=body.get("case_id"),
            analyst="authenticated_admin",
            decision=body.get("decision"),
            justification=body.get("justification"),
        )
    except (ValueError, TypeError):
        return jsonify({
            "status": "error",
            "message": "Invalid analyst decision"
        }), 400

    case_id = decision["case_id"]
    report = soc_case_registry.claim(case_id)

    if report is None:
        return jsonify({
            "status": "error",
            "message": "SOC case unavailable or already reviewed"
        }), 409

    try:
        decision["case_classification"] = report["classification"]
        decision["case_status"] = "REVIEWED"
        from phase7_soc.offline_audit import append_decision
        audit = append_decision(
            Path(__file__).resolve().parent.parent / "phase7_soc" / "artifacts" / "offline_soc_audit.jsonl",
            decision,
        )
        decision.update(audit)

        if not soc_case_registry.complete(case_id):
            raise RuntimeError("Could not complete SOC case")

    except Exception:
        app.logger.exception("Offline SOC case review failed")
        soc_case_registry.release(case_id)
        return jsonify({
            "status": "error",
            "message": "SOC case review failed"
        }), 500

    return jsonify({
        "status": "success",
        "decision": decision,
        "enforcement_enabled": False,
        "action_executed": False,
    })


# Offline-only research endpoint. Never invokes trained models.
@app.route("/api/phase6/offline-pcap-features", methods=["GET"])
@require_admin
def phase6_offline_pcap_features():
    if not NOVASHIELD_OFFLINE_ONLY:
        return jsonify({
            "status": "disabled",
            "message": "Requires offline-only mode"
        }), 503

    from pathlib import Path
    import importlib.util

    project_root = Path(__file__).resolve().parent.parent

    fixture = (
        project_root
        / "research_fixtures"
        / "novashield_synthetic_tcp.pcap"
    )

    metadata_path = (
        project_root
        / "phase6_xai"
        / "artifacts"
        / "model_metadata.json"
    )

    if (
        not fixture.is_file()
        or fixture.is_symlink()
        or not metadata_path.is_file()
        or metadata_path.is_symlink()
    ):
        return jsonify({
            "status": "error",
            "message": "Allowlisted offline files unavailable"
        }), 503

    try:
        from scapy.all import rdpcap

        scripts_dir = project_root / "scripts"

        def load_research_module(name):
            path = scripts_dir / (name + ".py")
            if not path.is_file() or path.is_symlink():
                raise ValueError("Research module unavailable")

            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                raise ValueError("Research module loader unavailable")

            module = importlib.util.module_from_spec(spec)
            import sys
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return module

        assembler_module = load_research_module(
            "novashield_flow_assembler"
        )
        exporter_module = load_research_module(
            "novashield_feature_exporter"
        )

        required = json.loads(
            metadata_path.read_text(encoding="utf-8")
        )["features"]

        if len(required) != 78 or len(set(required)) != 78:
            raise ValueError("Invalid model feature metadata")

        packets = rdpcap(str(fixture))
        assembler = assembler_module.FlowAssembler()

        for packet in packets:
            assembler.add_packet(packet)

        flows = (
            list(assembler.completed_flows)
            + list(assembler.flows.values())
        )

        if len(flows) != 1:
            raise ValueError(
                "Expected exactly one synthetic research flow"
            )

        measured = exporter_module.export_partial_features(flows[0])

        values = exporter_module.require_complete_vector(
            measured, required
        )

        return jsonify({
            "status": "success",
            "mode": "offline_pcap_research",
            "source": "allowlisted_synthetic_pcap",
            "packet_count": len(packets),
            "flow_count": len(flows),
            "feature_count": len(values),
            "features": {
                name: float(value)
                for name, value in zip(required, values)
            },
            "ai_status": "not_run",
            "ai_reason": "CICFlowMeter feature-value parity unverified",
            "enforcement_enabled": False
        })

    except (ValueError, KeyError, OSError) as exc:
        return jsonify({
            "status": "error",
            "message": str(exc)
        }), 422


# NX-03 captured PCAP flow summary (offline research only)
@app.route("/api/phase6/captured-pcap-flows", methods=["GET"])
@require_admin
def phase6_captured_pcap_flows():
    from datetime import datetime
    if not NOVASHIELD_OFFLINE_ONLY:
        return jsonify({"status": "disabled", "message": "Requires offline-only mode"}), 503

    from pathlib import Path
    import importlib.util
    import sys
    from scapy.all import PcapReader, IP, TCP

    root = Path(__file__).resolve().parent.parent
    capture = root / "research_fixtures/live_capture/en0_test.pcap"
    if not capture.is_file() or capture.is_symlink():
        return jsonify({"status": "error", "message": "Capture unavailable"}), 404
    if capture.stat().st_size > 20 * 1024 * 1024:
        return jsonify({"status": "error", "message": "Capture exceeds 20 MB research limit"}), 413

    try:
        module_path = root / "scripts/novashield_flow_assembler.py"
        if not module_path.is_file() or module_path.is_symlink():
            raise ValueError("Flow assembler unavailable")
        spec = importlib.util.spec_from_file_location("novashield_capture_flow_assembler", module_path)
        if spec is None or spec.loader is None:
            raise ValueError("Flow assembler loader unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        assembler = module.FlowAssembler()
        packets = processed = skipped = 0
        with PcapReader(str(capture)) as reader:
            for packet in reader:
                packets += 1
                if packets > 50000:
                    raise ValueError("Capture exceeds 50,000-packet research limit")
                if IP not in packet or TCP not in packet:
                    skipped += 1
                    continue
                try:
                    assembler.add_packet(packet)
                    processed += 1
                except (ValueError, IndexError):
                    skipped += 1

        flows = len(assembler.completed_flows) + len(assembler.flows)
        return jsonify({
            "status": "success",
            "mode": "offline_captured_pcap_summary",
            "source": "fixed_local_en0_capture",
            "packet_count": packets,
            "tcp_packet_count": processed,
            "flow_count": flows,
            "skipped_packet_count": skipped,
            "feature_status": "not_validated_full_snaplen",
            "ai_status": "not_run",
            "enforcement_enabled": False,
            "capture_modified_at": datetime.fromtimestamp(capture.stat().st_mtime).astimezone().isoformat(),
            "live_capture_active": False
        })
    except (OSError, ValueError, ImportError) as exc:
        return jsonify({"status": "error", "message": str(exc)}), 422



# NX-01: Read-only completed observation telemetry.
# Does not start capture, run inference, or execute enforcement.
@app.route("/api/telemetry", methods=["GET"])
@require_admin
def api_telemetry():
    from datetime import datetime, timezone
    import stat

    root = Path(__file__).resolve().parent.parent
    directory = root / "records" / "telemetry"
    snapshot_path = directory / "latest.json"

    try:
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("Telemetry directory unavailable")

        directory_stat = directory.stat()
        if (
            directory_stat.st_uid != os.getuid()
            or stat.S_IMODE(directory_stat.st_mode) != 0o700
        ):
            raise ValueError("Telemetry directory permissions invalid")

        if snapshot_path.is_symlink() or not snapshot_path.is_file():
            return jsonify({
                "status": "unavailable",
                "message": "No completed observation available",
                "capture_active": False,
            }), 404

        file_stat = snapshot_path.stat()
        if (
            file_stat.st_uid != os.getuid()
            or stat.S_IMODE(file_stat.st_mode) != 0o600
            or file_stat.st_size > 16384
        ):
            raise ValueError("Telemetry snapshot permissions or size invalid")

        with snapshot_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        if not isinstance(data, dict):
            raise ValueError("Invalid telemetry document")

        counts = data.get("protocol_counts")
        total = data.get("observed_packet_lines")
        if (
            data.get("schema_version") != 1
            or data.get("source") != "isolated_tcpdump_observer"
            or data.get("provenance") not in ("synthetic_test", "operator_observed")
            or data.get("mode") != "observation_only"
            or data.get("capture_status") not in (
                "process_complete", "packet_limit", "time_limit"
            )
            or data.get("capture_active") is not False
            or data.get("ai_status") != "not_run"
            or data.get("enforcement_enabled") is not False
            or not isinstance(total, int)
            or isinstance(total, bool)
            or not 0 <= total <= 100
            or not isinstance(counts, dict)
        ):
            raise ValueError("Telemetry schema validation failed")

        required_counts = ("tcp", "udp", "other", "ipv4", "ipv6")
        if any(
            not isinstance(counts.get(name), int)
            or isinstance(counts.get(name), bool)
            or counts[name] < 0
            for name in required_counts
        ):
            raise ValueError("Invalid protocol counters")

        if (
            counts["tcp"] + counts["udp"] + counts["other"] != total
            or counts["ipv4"] + counts["ipv6"] != total
        ):
            raise ValueError("Telemetry counter mismatch")

        interface = data.get("interface")
        if (
            not isinstance(interface, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", interface)
        ):
            raise ValueError("Invalid capture interface")

        collected_at = data.get("collected_at")
        if not isinstance(collected_at, str):
            raise ValueError("Invalid observation timestamp")

        timestamp = datetime.fromisoformat(collected_at)
        if timestamp.utcoffset() is None:
            raise ValueError("Observation timestamp missing timezone")

        age_seconds = (datetime.now(timezone.utc) - timestamp).total_seconds()
        if age_seconds < -60:
            raise ValueError("Observation timestamp is in the future")

        return jsonify({
            "status": "success",
            "mode": "completed_observation",
            "provenance": data["provenance"],
            "source": data["source"],
            "interface": interface,
            "collected_at": collected_at,
            "age_seconds": max(0, round(age_seconds, 1)),
            "capture_status": data["capture_status"],
            "capture_active": False,
            "observed_packet_lines": total,
            "protocol_counts": {
                name: counts[name] for name in required_counts
            },
            "ai_status": "not_run",
            "enforcement_enabled": False,
        })

    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        app.logger.warning("Telemetry snapshot unavailable or invalid")
        return jsonify({
            "status": "unavailable",
            "message": "Telemetry snapshot invalid or unavailable",
            "capture_active": False,
        }), 503


if __name__ == '__main__':
    start_socket_cleanup_worker()
    try:
        print("Starting NovaShield Dashboard on http://127.0.0.1:5000")
        socketio.run(app, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)
    finally:
        stop_socket_cleanup_worker()