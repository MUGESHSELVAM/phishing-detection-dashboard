from flask import Blueprint, render_template
from db import get_db

admin_bp = Blueprint('admin', __name__, template_folder='templates')

@admin_bp.route('/admin')
def admin_home():
    db = get_db()
    scans = db.scans
    total = scans.count_documents({})
    phishing_count = scans.count_documents({"prediction": "phishing"})
    recent = list(scans.find().sort("timestamp", -1).limit(10))
    legitimate_count = scans.count_documents({"prediction": "legitimate"})
    # risk distribution
    pipeline = [
        {"$group": {"_id": "$risk_score", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]
    dist = list(scans.aggregate(pipeline))
    # top suspicious domains
    top_domains = list(scans.aggregate([
        {"$group": {"_id": "$url", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]))
    return render_template('admin.html', total=total, phishing_count=phishing_count, legitimate_count=legitimate_count, recent=recent, distribution=dist, top_domains=top_domains)
