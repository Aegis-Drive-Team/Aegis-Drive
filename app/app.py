from flask import Flask, render_template, request, redirect, url_for, session, flash
from api_driver import api_query, api_query_search, fetch_blacklist, report_to_ipabusedb
from auth import verify_user, create_user
from db_post import create_ip_report, upsert_enrichment_from_abuseipdb, get_supabase, get_reports_for_ip
#from db_users import create_user
from functools import wraps
from dotenv import load_dotenv
import os
import re
from datetime import datetime
from flask_dropzone import Dropzone
import sqlite3
from collections import Counter
import re
import socket

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_fallback_key")  # store securely in .env
app.config.update(
    UPLOAD_FOLDER='uploads',
    DROPZONE_MAX_FILE_SIZE=10, # MB
    DROPZONE_ALLOWED_FILE_TYPE='image',
    DROPZONE_UPLOAD_MULTIPLE=True,
    DROPZONE_UPLOAD_BTN_ID='submit-button'
)
dropzone = Dropzone(app)

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to continue.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))

        if session.get('role') != 'admin':
            flash("You do not have permission to perform this action.")
            return redirect(url_for('dashboard'))  # or wherever

        return f(*args, **kwargs)
    return decorated

# Dynamic list of IPs (initial examples)
ip_list = []
#"192.168.1.10", "8.8.8.8", "1.1.1.1"]

searched_domains = []

# Dashboard route (public)
@app.route("/")
@login_required
def dashboard():
    search = request.args.get("search", "").lower()
    records = []    

    for ip in ip_list:
        try:
            data = api_query(ip)
            if isinstance(data, list):
                data = data[0]
            hostname = data.get("hostname", "")
            domain = data.get("domain", "")

            if not search or search in ip.lower() or search in hostname.lower() or search in domain.lower():
                records.append(data)
        except Exception as e:
            print(f"Error querying {ip}: {e}")

    return render_template("layout.html", records=records, search=search, searched_domains=searched_domains)

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user = verify_user(username, password)
        print("incorrect username or password")

        if user:
            session["username"] = user["username"]
            session["role"] = user["role"]     # ➤ fixed: store only the role string
            session["user_id"] = user["id"]    # ➤ optional but useful

            flash(f"Welcome, {username}!")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials.")

    return render_template("login.html")

# Logout route
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("login"))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        try:
            create_user(username, password)
            flash("Account created! You can now log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error creating account: {e}", "danger")

    return render_template("signup.html")


# Search route (public)
@app.route("/search")
def search():
    """Shows page where user can search and find reports for IPs or domains."""
    query = request.args.get("search", "").strip()
    record = {}

    # Prepare histogram data
    now = datetime.now()
    dates = list(range(1, 13))
    current_month = now.month
    data_graph = [0] * 12
    labels = dates.copy()
    for _ in range(12 - current_month):
        dates.insert(0, dates.pop())

    role = session.get("role", "user")

    # Detect if query is IP or domain
    def is_ip(v):
        return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v) is not None

    is_domain = (not is_ip(query)) and "." in query

    internal_reports = []

    if is_domain:
    
    # Store domain for dashboard
        if is_domain and 'username' in session:
    # Only add if domain is not already in searched_domains
           if not any(d["domain"] == query for d in searched_domains):
               searched_domains.append({
                   "domain": query,
                   "searched_by": session.get('username'),
                   "searched_at": datetime.now()
               })


    if query:
        try:
            if is_domain:
                # --------------------------
                # DOMAIN SEARCH
                # --------------------------
                record = {
                    "domain": query,
                    "hostname": "N/A",
                    "ipAddresses": [],
                    "abuseConfidenceScore": "N/A",
                    "reports": [],
                    "ipDetails": [],
                    "internalReports": [],
                }

                try:
                    resolved_ips = socket.gethostbyname_ex(query)[2]  # list of IPs
                except Exception as e:
                    print(f"[WARN] Failed to resolve domain {query}: {e}")
                    resolved_ips = []

                record["ipAddresses"] = resolved_ips

                for ip in resolved_ips:
                    # Reuse IP lookup logic
                    data = api_query_search(ip, verbose=True, max_report_age=365, role=role)
                    if isinstance(data, list):
                        data = data[0]

                    if "error" not in data:
                        record["ipDetails"].append(data)

                        # Create abuse report if user is logged in
                        if 'username' in session:
                            score = data.get("abuseConfidenceScore")
                            category = "suspicious" if isinstance(score, (int, float)) and score >= 50 else "benign"

                            create_ip_report(
                                ip=ip,
                                category=category,
                                description=f"Domain {query} associated IP lookup: score={score}, isp={data.get('isp')}, usageType={data.get('usageType')}",
                                source="domain_lookup",
                                reporter_id=session.get("username"),
                            )

                            upsert_enrichment_from_abuseipdb(
                                ip=ip,
                                abuse_score_0_to_100=score if isinstance(score, (int, float)) else None,
                                evidence={"domain": query, "hostname": data.get("hostname")},
                            )

                    # Internal reports for this IP
                    try:
                        reports = get_reports_for_ip(ip, role=role)
                        record["internalReports"].extend(reports)
                    except Exception as e:
                        print(f"[WARN] Failed to load internal reports for {ip}: {e}")

            else:
                # --------------------------
                # IP SEARCH
                # --------------------------
                data = api_query_search(query, verbose=True, max_report_age=365, role=role)
                if isinstance(data, list):
                    data = data[0]

                if "error" not in data:
                    record = data

                    if 'username' in session and query not in ip_list:
                        ip_list.append(query)

                    try:
                        score = record.get("abuseConfidenceScore")
                        category = "suspicious" if isinstance(score, (int, float)) and score >= 50 else "benign"

                        if 'username' in session:
                            create_ip_report(
                                ip=record.get("ip"),
                                category=category,
                                description=f"AbuseIPDB lookup: score={score}, isp={record.get('isp')}, usageType={record.get('usageType')}",
                                source="abuseipdb",
                                reporter_id=session.get("username"),
                            )

                            upsert_enrichment_from_abuseipdb(
                                ip=record.get("ip"),
                                abuse_score_0_to_100=score if isinstance(score, (int, float)) else None,
                                evidence={"domain": record.get("domain"), "hostname": record.get("hostname")},
                            )
                    except Exception as e:
                        print(f"[WARN] Supabase insert failed: {e}")

                # Load internal reports
                try:
                    internal_reports = get_reports_for_ip(query, role=role)
                except Exception as e:
                    print(f"[WARN] Failed to load internal reports for {query}: {e}")

        except Exception as e:
            print(f"[ERROR] Lookup failed for {query}: {e}")
            record = {
                "input": query,
                "hostname": "N/A",
                "domain": "N/A",
                "abuseConfidenceScore": "N/A",
            }

    # Ensure defaults if record is empty
    if not record:
        record = {
            "input": query,
            "hostname": "N/A",
            "domain": "N/A",
            "abuseConfidenceScore": "N/A",
        }

    # Filter reports for non-admin users (IP reports)
    if "reports" in record:
        record["reports"] = [
            r for r in record["reports"]
            if r.get("public", True) or role == "admin"
        ]

        # loop for report data by date
        for report in record["reports"]:
            reported_date = report.get('reportedAt')
            # if there is a date
            if reported_date:
                # get the month out fo date
                month = int(reported_date[5:7])
                # iterate report number at each date
                for i, d in enumerate(dates):
                    if month == d:
                        data_graph[i] += 1

    # If domain, also count internalReports in histogram
    if is_domain and "internalReports" in record:
        for report in record["internalReports"]:
            reported_date = report.get('reportedAt')
            if reported_date:
                month = int(reported_date[5:7])
                for i, d in enumerate(dates):
                    if month == d:
                        data_graph[i] += 1

    return render_template(
        "search.html",
        search=query,
        record=record,
        labels=labels,
        data=data_graph,
        internal_reports=internal_reports if not is_domain else record.get("internalReports", []),
    )


# Add a new IP (login required)
@app.route("/add_ip", methods=["POST"])
@admin_required
def add_ip():
    new_ip = request.form.get("new_ip")
    if new_ip and new_ip not in ip_list:
        try:
            data = api_query(new_ip)
            if isinstance(data, list):
                data = data[0]
            ip_list.append(new_ip)
        except Exception as e:
            return f"Error adding IP: {e}", 400
    return redirect("/")

# Bulk import IPs from API (login required)
@app.route("/bulk_import_api")
@admin_required
def bulk_import_api():
    try:
        new_ips = fetch_blacklist(limit=50)
        for ip in new_ips:
            if ip not in ip_list:
                ip_list.append(ip)
    except Exception as e:
        return f"Error during bulk import: {e}", 500
    return redirect("/")

@app.route("/report_ip", methods=["GET", "POST"])
@login_required
def report_ip():
    """ page allows the user to report an ip address using our internal database """

    if request.method == 'POST':
        report_ip = request.form.get('report_ip')
        report_msg = request.form.get('report_msg')
        category = request.form.get("category", "suspicious")
        source = "manual"

        public = request.form.get("public") == "on"

        create_ip_report(
            ip=report_ip,
            category=category,
            description=report_msg,
            source=source,
            reporter_id=session.get("username"),
            public=public
        )

        # External reporting option
        if public:
            report_to_ipabusedb(report_ip, report_msg)
        
        ip_list.append(report_ip)

        return render_template(
            "report_success.html",
            report_ip=report_ip,
            report_msg=report_msg,
            category=category
        )

    return render_template("report_ip.html")


@app.route("/upload", methods=["GET", "POST"])
@admin_required
def upload():
    """ page to upload file to the website """ 
    print(type(request))
    # check if post 
    if request.method == 'POST':
        # for each file uploaded
        for key, f in request.files.items():
            # load each file
            iterator = 0
            if key.startswith('file'):
                print("hey what is this:",f.name)
                # generate a good file name, I'm thinking date time, and probably have a folder for each user
                # this is not super scalable, but works for now I hope
                date = datetime.now()
                time_thing = str(date.month) + "." + str(date.day) + "." + str(date.year)
                file_name = time_thing + "(" + str(iterator) + ")"
                file_name = os.path.join(app.config["UPLOAD_FOLDER"], file_name + ".data")
                f.save(file_name)
                iterator = iterator + 1
        # open the file
        # parse its contents
        # print the contents return it
        ip_list.extend(set(ssh_file_parse(file_name)))
        return """ please return to the dash board to see IP addresses.
                <li class="nav-item"><a class="nav-link" href="/">Dashboard</a></li>
        """
    else:
        return render_template("upload.html")

# upload test results
@app.route("/upload_results")
def upload_results():
    """" the next part after the log has been uploaded """
    # kind  think it would be cool if we got all the ip's
    # then you have all the mentioned ip's, and be able to reportt the etc there
    # oooh wiat then we could have a hyper link to each of those ips


""" this code no longer functions as expected... """
#	def get_reports_for_ip(ip: str, role: str = "user", limit: int = 50) -> 
#	list[dict]:
#    try:
#        query = get_supabase().table('ip_reports').select('*').eq('ip', ip)
#
#        if role != "admin":
#            query = query.eq('public', True)
#
#
#        response = query.order('created_at', desc=True).limit(limit).execute()
#        return response.data if response.data else []
#   except Exception as e:
#       raise RuntimeError(f"Failed to get reports: {e}")
#
#
# @app.route("/toggle_public/<int:report_id>", methods=["POST"])
# @admin_required
# def toggle_public(report_id):
#     public = request.form.get("public") == "on"
#     conn = get_connection()
#     cur = conn.cursor()
#     cur.execute("UPDATE ip_reports SET public=? WHERE id=?", (public, report_id))
#     conn.commit()
#     conn.close()
#     flash(f"Report visibility updated.")
#     return redirect(request.referrer or url_for("dashboard"))

@app.route("/ip/<ip>")
@login_required
def ip_details(ip):
    role = session.get("role", "user")
    record = {}

        # --- INTERNAL REPORTS (same method as search page) ---
    try:
        internal_reports = get_reports_for_ip(
            ip,
            role=session.get("role", "user")
        )
    except Exception as e:
        print(f"[WARN] Failed to load internal reports for {ip}: {e}")
        internal_reports = []

  
    try:
        data = api_query_search(ip, verbose=True, max_report_age=365, role=role)
        if isinstance(data, list):
            data = data[0]

        if "error" not in data:
            record = data
        else:
             record = {"ip": ip, "hostname": "N/A", "domain": "N/A", "abuseConfidenceScore": "N/A"}

    except Exception:
        record = {"ip": ip, "hostname": "N/A", "domain": "N/A", "abuseConfidenceScore": "N/A"}


    # --- CATEGORY CHART ---
    try:
        reports = get_reports_for_ip(ip, role=role)
    except Exception as e:
        flash(f"Failed to load reports for {ip}: {e}", "danger")
        reports = []

    visible_reports = [
        r for r in reports if r.get("public", True) or role == "admin"
    ]

    category_counts = Counter()
    for report in visible_reports:
        cat = report.get("category", "unknown")
        category_counts[cat] += 1

    category_labels = list(category_counts.keys())
    category_data = list(category_counts.values())
    
    now = datetime.now()
    dates = list(range(1, 13))
    # dates = [0] * 12
    current_month = now.month
    
    for _ in range(12 - current_month):
        dates.insert(0, dates.pop())

    # coltens code
    # Prepare histogram data
    now = datetime.now()
    dates = list(range(1, 13))
    current_month = now.month
    data_graph = [0] * 12
    labels = dates.copy()
    for _ in range(12 - current_month):
        dates.insert(0, dates.pop())


    # --- ABUSEIPDB LINE DATA ---
    abuse_line_data = [0] * 12

    print(type(record))
    # huh
    if "reports" in record:
        record["reports"] = [
            r for r in record["reports"]
            if r.get("public", True) or role == "admin"
        ]
        print(visible_reports)
        for report in visible_reports:
            reported_date = report.get("reportedAt")
            print(reported_date)
            if reported_date:
                month = int(reported_date[5:7])
                for i, d in enumerate(dates):
                    if month == d:
                        abuse_line_data[i] += 1

    # Filter reports for non-admin users (IP reports)
    if "reports" in record:
        record["reports"] = [
            r for r in record["reports"]
            if r.get("public", True) or role == "admin"
        ]

        # loop for report data by date
        for report in record["reports"]:
            reported_date = report.get('reportedAt')
            # if there is a date
            if reported_date:
                # get the month out fo date
                month = int(reported_date[5:7])
                # iterate report number at each date
                for i, d in enumerate(dates):
                    if month == d:
                        data_graph[i] += 1

    return render_template(
    "ip_details.html",
    ip=ip,
    reports=visible_reports,
    category_labels=category_labels or [],
    category_data=category_data or [],
    line_labels=labels,
    line_data=data_graph,
    record=record,
    internal_reports=internal_reports,
)





def get_line_chart_data(ip):
    """Return monthly report counts for the given IP."""
    role = session.get("role", "user")
    reports = get_reports_for_ip(ip)

    # Filter visible reports
    reports = [r for r in reports if r.get("public", True) or role == "admin"]

    # Initialize month counts
    months = list(range(1, 13))
    counts = [0] * 12

    for report in reports:
        reported_date = report.get("reportedAt")
        if reported_date:
            month = int(reported_date[5:7])
            for i, m in enumerate(months):
                if m == month:
                    counts[i] += 1

    return months, counts

def ssh_file_parse(filename :str):
    """ open file and return contents"""
    with open(filename, 'r') as file:
        file_content = file.read()
    found_ips = list()

    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

    found_ips.extend(re.findall(ip_pattern, file_content))
    print(found_ips)    

    return found_ips


# Edit IP (admin only)
@app.route("/edit/<ip>")
@admin_required
def edit_ip(ip):
    return f"Edit page for {ip} (to be implemented)"

# Delete IP (admin only)
@app.route("/delete/<ip>")
@admin_required
def delete_ip(ip):
    return f"Delete {ip} (confirmation page to be implemented)"

# Monitor IP (admin only)
@app.route("/monitor/<ip>")
@admin_required
def monitor_ip(ip):
    return f"Monitoring details for {ip} (coming soon)"

if __name__ == "__main__":
    
    app.run(debug=True)