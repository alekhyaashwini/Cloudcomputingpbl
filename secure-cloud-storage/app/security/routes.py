import csv
import io
from flask import Blueprint, render_template, request, session, current_app, Response
from app.auth.routes import login_required

security_bp = Blueprint('security', __name__, url_prefix='/security')

@security_bp.route('/')
@login_required
def index():
    event_filter = request.args.get('event_type', '').strip() or None
    audit_logs = current_app.db.get_audit_logs(limit=100, event_type=event_filter)
    
    # Calculate security metrics
    total_events = len(audit_logs)
    security_alerts = sum(1 for log in audit_logs if log['status'] == 'SECURITY_ALERT')
    successful_ops = sum(1 for log in audit_logs if log['status'] == 'SUCCESS')
    warnings = sum(1 for log in audit_logs if log['status'] == 'WARNING')
    
    storage_backend = current_app.config['STORAGE_BACKEND'].upper()
    bucket_or_path = current_app.config.get('S3_BUCKET_NAME') if storage_backend == 'S3' else current_app.config.get('LOCAL_STORAGE_DIR')

    return render_template(
        'security.html',
        audit_logs=audit_logs,
        total_events=total_events,
        security_alerts=security_alerts,
        successful_ops=successful_ops,
        warnings=warnings,
        storage_backend=storage_backend,
        bucket_or_path=bucket_or_path,
        selected_event=event_filter,
        username=session.get('username')
    )

@security_bp.route('/export_audit_logs')
@login_required
def export_audit_logs():
    """Generates downloadable CSV export of security audit events."""
    audit_logs = current_app.db.get_audit_logs(limit=500)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Actor/Username', 'Event Type', 'Details', 'IP Address', 'Status'])
    
    for log in audit_logs:
        writer.writerow([
            log['id'],
            log['created_at'],
            log['username'],
            log['event_type'],
            log['details'],
            log['ip_address'],
            log['status']
        ])
    
    csv_bytes = output.getvalue().encode('utf-8')
    return Response(
        csv_bytes,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=securecloud_audit_trail.csv"}
    )
