# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, g
from functools import wraps
import sqlite3
import csv
import io
import logging
from datetime import datetime, date
import matplotlib
matplotlib.use("Agg")  # Use a non-GUI backend for rendering figures
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import matplotlib.pyplot as plt
import base64

# ----------------------------
# Setup Logging
# ----------------------------
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s'
)

# ----------------------------
# Database Manager Class
# ----------------------------
class DatabaseManager:
    def __init__(self, db_name="fund_manager.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row  # rows behave like dictionaries
        self.create_tables()

    def create_tables(self):
        c = self.conn.cursor()
        # Users table
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT
            )
        """)
        # Insert default admin accounts if none exist
        c.execute("SELECT COUNT(*) as count FROM users")
        count = c.fetchone()["count"]
        if count == 0:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin1", "admin1", "admin"))
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin2", "admin2", "admin"))
            logging.info("Inserted default admin accounts.")
        # Contributors table
        c.execute("""
            CREATE TABLE IF NOT EXISTS contributors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                type TEXT,
                login_username TEXT
            )
        """)
        c.execute("PRAGMA table_info(contributors)")
        cols = [row["name"] for row in c.fetchall()]
        if "login_username" not in cols:
            c.execute("ALTER TABLE contributors ADD COLUMN login_username TEXT")
            self.conn.commit()
        # Transactions table
        c.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contributor_id INTEGER,
                date TEXT,
                type TEXT,
                amount REAL,
                asset TEXT,
                allocated_charges REAL,
                comment TEXT,
                FOREIGN KEY (contributor_id) REFERENCES contributors(id)
            )
        """)
        # Trades table
        c.execute("""
            CREATE TABLE IF NOT EXISTS trades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trade_date TEXT,
                asset TEXT,
                pnl REAL,
                charges REAL,
                commission REAL,
                net_pnl REAL,
                net_profit_after_commission REAL,
                comment TEXT
            )
        """)
        # Withdrawal Requests table
        c.execute("""
            CREATE TABLE IF NOT EXISTS withdrawal_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contributor_id INTEGER,
                request_date TEXT,
                amount REAL,
                comment TEXT,
                status TEXT DEFAULT 'pending',
                approved_date TEXT,
                admin_comment TEXT,
                FOREIGN KEY (contributor_id) REFERENCES contributors(id)
            )
        """)
        self.conn.commit()

    # User management functions:
    def add_user(self, username, password, role="user"):
        c = self.conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
            self.conn.commit()
            logging.info(f"Added user: {username} with role {role}")
            return c.lastrowid
        except sqlite3.IntegrityError:
            raise Exception(f"User '{username}' already exists.")

    def update_user(self, user_id, username, password, role):
        c = self.conn.cursor()
        c.execute("UPDATE users SET username=?, password=?, role=? WHERE id=?", (username, password, role, user_id))
        self.conn.commit()
        logging.info(f"Updated user id {user_id}")

    def get_all_users(self):
        c = self.conn.cursor()
        c.execute("SELECT * FROM users ORDER BY username")
        return c.fetchall()

    def verify_user(self, username, password):
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        return c.fetchone()

    # Contributor functions:
    def add_contributor(self, name, ctype, login_username=None):
        c = self.conn.cursor()
        try:
            c.execute("INSERT INTO contributors (name, type, login_username) VALUES (?, ?, ?)", (name, ctype, login_username))
            self.conn.commit()
            contributor_id = c.lastrowid
            logging.info(f"Added contributor: {name} ({ctype}) with login '{login_username}'")
            return contributor_id
        except sqlite3.IntegrityError:
            raise Exception(f"Contributor '{name}' already exists.")

    def update_contributor(self, contributor_id, name, ctype):
        c = self.conn.cursor()
        c.execute("UPDATE contributors SET name=?, type=? WHERE id=?", (name, ctype, contributor_id))
        self.conn.commit()
        logging.info(f"Updated contributor id {contributor_id}")

    def update_contributor_login(self, contributor_id, login_username):
        c = self.conn.cursor()
        c.execute("UPDATE contributors SET login_username=? WHERE id=?", (login_username, contributor_id))
        self.conn.commit()
        logging.info(f"Assigned login '{login_username}' to contributor id {contributor_id}")

    def get_all_contributors(self):
        c = self.conn.cursor()
        c.execute("SELECT * FROM contributors ORDER BY name")
        return c.fetchall()

    def get_contributor_by_id(self, contributor_id):
        c = self.conn.cursor()
        c.execute("SELECT * FROM contributors WHERE id=?", (contributor_id,))
        return c.fetchone()

    def get_contributor_by_login(self, login_username):
        c = self.conn.cursor()
        c.execute("SELECT * FROM contributors WHERE login_username=?", (login_username,))
        return c.fetchone()

    # Transaction and Trade functions:
    def add_transaction(self, contributor_id, date_str, txn_type, amount, asset, allocated_charges, comment):
        c = self.conn.cursor()
        c.execute("""
            INSERT INTO transactions (contributor_id, date, type, amount, asset, allocated_charges, comment)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (contributor_id, date_str, txn_type, amount, asset, allocated_charges, comment))
        self.conn.commit()
        logging.info(f"Added transaction for contributor_id {contributor_id}: {txn_type} of {amount} on {date_str}")

    def update_transaction(self, txn_id, contributor_id, date_str, txn_type, amount, asset, allocated_charges, comment):
        c = self.conn.cursor()
        c.execute("""
            UPDATE transactions 
            SET contributor_id=?, date=?, type=?, amount=?, asset=?, allocated_charges=?, comment=?
            WHERE id=?
        """, (contributor_id, date_str, txn_type, amount, asset, allocated_charges, comment, txn_id))
        self.conn.commit()
        logging.info(f"Updated transaction id {txn_id}")

    def add_trade(self, trade_date, asset, pnl, charges, commission, net_pnl, net_profit_after_commission, comment):
        c = self.conn.cursor()
        c.execute("""
            INSERT INTO trades (trade_date, asset, pnl, charges, commission, net_pnl, net_profit_after_commission, comment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (trade_date, asset, pnl, charges, commission, net_pnl, net_profit_after_commission, comment))
        self.conn.commit()
        trade_id = c.lastrowid
        logging.info(f"Recorded trade: {asset} on {trade_date} with net profit {net_profit_after_commission}")
        return trade_id

    def update_trade(self, trade_id, trade_date, asset, pnl, charges, commission, net_pnl, net_profit_after_commission, comment):
        c = self.conn.cursor()
        c.execute("""
            UPDATE trades 
            SET trade_date=?, asset=?, pnl=?, charges=?, commission=?, net_pnl=?, net_profit_after_commission=?, comment=?
            WHERE id=?
        """, (trade_date, asset, pnl, charges, commission, net_pnl, net_profit_after_commission, comment, trade_id))
        self.conn.commit()
        logging.info(f"Updated trade id {trade_id}")

    def get_all_transactions(self):
        c = self.conn.cursor()
        c.execute("SELECT * FROM transactions ORDER BY date")
        return c.fetchall()

    def get_transactions_for_contributor(self, contributor_id):
        c = self.conn.cursor()
        c.execute("SELECT * FROM transactions WHERE contributor_id=? ORDER BY date", (contributor_id,))
        return c.fetchall()

    def get_all_trades(self):
        c = self.conn.cursor()
        c.execute("SELECT * FROM trades ORDER BY trade_date")
        return c.fetchall()

    def get_eligible_balance(self, contributor_id, as_of_date):
        c = self.conn.cursor()
        c.execute("SELECT SUM(amount) as total FROM transactions WHERE contributor_id=? AND date<=?", (contributor_id, as_of_date))
        result = c.fetchone()
        return result["total"] if result["total"] is not None else 0.0

    def get_total_fund(self, as_of_date):
        c = self.conn.cursor()
        c.execute("SELECT SUM(amount) as total FROM transactions WHERE date<=?", (as_of_date,))
        result = c.fetchone()
        return result["total"] if result["total"] is not None else 0.0

    # Withdrawal Requests functions:
    def add_withdrawal_request(self, contributor_id, request_date, amount, comment):
        c = self.conn.cursor()
        c.execute("""
            INSERT INTO withdrawal_requests (contributor_id, request_date, amount, comment, status)
            VALUES (?, ?, ?, ?, 'pending')
        """, (contributor_id, request_date, amount, comment))
        self.conn.commit()
        logging.info(f"Added withdrawal request for contributor_id {contributor_id}: amount {amount} on {request_date}")
        return c.lastrowid

    def get_withdrawal_requests(self, status=None):
        c = self.conn.cursor()
        if status:
            c.execute("SELECT * FROM withdrawal_requests WHERE status=? ORDER BY request_date", (status,))
        else:
            c.execute("SELECT * FROM withdrawal_requests ORDER BY request_date")
        return c.fetchall()

    def get_withdrawal_requests_for_contributor(self, contributor_id):
        c = self.conn.cursor()
        c.execute("SELECT * FROM withdrawal_requests WHERE contributor_id=? ORDER BY request_date", (contributor_id,))
        return c.fetchall()

    def update_withdrawal_request(self, request_id, status, approved_date, admin_comment):
        c = self.conn.cursor()
        c.execute("""
            UPDATE withdrawal_requests 
            SET status=?, approved_date=?, admin_comment=?
            WHERE id=?
        """, (status, approved_date, admin_comment, request_id))
        self.conn.commit()
        logging.info(f"Updated withdrawal request id {request_id} to status {status}")

    def close(self):
        self.conn.close()

# ----------------------------
# Create the Flask App Instance
# ----------------------------
app = Flask(__name__)
app.secret_key = "YOUR_SECRET_KEY"  # Replace with a secure key in production

# ----------------------------
# Per-Request Database Connection
# ----------------------------
def get_db():
    if 'db' not in g:
        g.db = DatabaseManager()  # New connection per request
    return g.db

@app.teardown_appcontext
def close_db(error):
    db_instance = g.pop('db', None)
    if db_instance is not None:
        db_instance.close()

# ----------------------------
# Login Decorators
# ----------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin access required.")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------
# Routes and Views
# ----------------------------

# Login Page
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            flash("Please enter both username and password.")
            return redirect(url_for("login"))
        db_instance = get_db()
        user = db_instance.verify_user(username, password)
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.")
            return redirect(url_for("login"))
    return render_template("login.html")

# Logout
@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("login"))

# Dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    db_instance = get_db()
    role = session.get("role")
    username = session.get("username")
    if role == "admin":
        txns = db_instance.get_all_transactions()
    else:
        contrib = db_instance.get_contributor_by_login(username)
        txns = db_instance.get_transactions_for_contributor(contrib["id"]) if contrib else []
    date_sums = {}
    deposit_total = 0.0
    trade_total = 0.0
    for txn in txns:
        txn_date = txn["date"]
        amt = txn["amount"]
        date_sums[txn_date] = date_sums.get(txn_date, 0) + amt
        if txn["type"] == "deposit":
            deposit_total += amt
        elif txn["type"] in ("trade", "withdrawal"):
            trade_total += amt
    dates = sorted(date_sums.keys())
    cum_sum = []
    total = 0.0
    for d in dates:
        total += date_sums[d]
        cum_sum.append(total)
    fig, (ax_growth, ax_pie) = plt.subplots(1, 2, figsize=(10,4))
    if dates:
        dates_dt = [datetime.strptime(d, '%Y-%m-%d') for d in dates]
        ax_growth.plot(dates_dt, cum_sum, marker='o')
        ax_growth.set_title("Cumulative Growth")
        ax_growth.set_xlabel("Date")
        ax_growth.set_ylabel("Amount (Rs)")
        ax_growth.grid(True)
    else:
        ax_growth.text(0.5, 0.5, "No Data Available", transform=ax_growth.transAxes, ha="center")
    labels = ['Deposits', 'Trades/Withdrawals']
    sizes = [deposit_total, abs(trade_total)]
    if sum(sizes) > 0:
        ax_pie.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        ax_pie.set_title("Breakdown")
    else:
        ax_pie.text(0.5, 0.5, "No Data", transform=ax_pie.transAxes, ha="center")
    canvas = FigureCanvas(fig)
    img = io.BytesIO()
    fig.savefig(img, format='png')
    img.seek(0)
    graph_url = base64.b64encode(img.getvalue()).decode()
    plt.close(fig)
    
    extra_metrics = None
    if role != "admin":
        contrib = db_instance.get_contributor_by_login(username)
        txns = db_instance.get_transactions_for_contributor(contrib["id"])
        total_deposits = sum(txn["amount"] for txn in txns if txn["type"]=="deposit")
        total_withdrawn = abs(sum(txn["amount"] for txn in txns if txn["type"]=="withdrawal"))
        current_balance = sum(txn["amount"] for txn in txns)
        roi = ((current_balance + total_withdrawn - total_deposits) / total_deposits * 100) if total_deposits > 0 else 0
        extra_metrics = {
            "total_deposits": total_deposits,
            "total_withdrawn": total_withdrawn,
            "current_balance": current_balance,
            "roi": roi
        }
    return render_template("dashboard.html", graph_url=graph_url, extra_metrics=extra_metrics, role=role, username=username)

# Add Contributor (admin only)
@app.route("/add_contributor", methods=["GET", "POST"])
@login_required
@admin_required
def add_contributor():
    db_instance = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        ctype = request.form.get("ctype", "").strip()
        deposit_str = request.form.get("deposit", "").strip()
        deposit_date = request.form.get("deposit_date", "").strip()
        login_username = request.form.get("login_username", "").strip()
        login_password = request.form.get("login_password", "").strip()
        if not name or not login_username or not login_password:
            flash("Please fill in the contributor name and login credentials.")
            return redirect(url_for("add_contributor"))
        try:
            deposit = float(deposit_str)
            if deposit <= 0:
                raise ValueError
        except ValueError:
            flash("Please enter a valid deposit amount greater than 0.")
            return redirect(url_for("add_contributor"))
        try:
            contributor_id = db_instance.add_contributor(name, ctype, login_username)
            db_instance.add_transaction(contributor_id, deposit_date, "deposit", deposit, "", 0.0, "Initial Deposit")
            db_instance.add_user(login_username, login_password, role="user")
            flash(f"Contributor '{name}' added with deposit Rs {deposit:.2f} on {deposit_date}. Login created for '{login_username}'.")
        except Exception as e:
            flash(str(e))
        return redirect(url_for("add_contributor"))
    return render_template("add_contributor.html")

# Add Funds (admin only)
@app.route("/add_funds", methods=["GET", "POST"])
@login_required
@admin_required
def add_funds():
    db_instance = get_db()
    contributors = db_instance.get_all_contributors()
    if request.method == "POST":
        name = request.form.get("contributor", "").strip()
        deposit_str = request.form.get("deposit", "").strip()
        deposit_date = request.form.get("deposit_date", "").strip()
        if not name:
            flash("Please select a contributor.")
            return redirect(url_for("add_funds"))
        try:
            deposit = float(deposit_str)
            if deposit <= 0:
                raise ValueError
        except ValueError:
            flash("Please enter a valid deposit amount greater than 0.")
            return redirect(url_for("add_funds"))
        contributor_id = None
        for row in contributors:
            if row["name"] == name:
                contributor_id = row["id"]
                break
        if contributor_id is not None:
            db_instance.add_transaction(contributor_id, deposit_date, "deposit", deposit, "", 0.0, "Additional Deposit")
            flash(f"Added Rs {deposit:.2f} to '{name}' on {deposit_date}.")
        else:
            flash("Contributor not found.")
        return redirect(url_for("add_funds"))
    return render_template("add_funds.html", contributors=contributors)

# Record Trade (admin only)
@app.route("/record_trade", methods=["GET", "POST"])
@login_required
@admin_required
def record_trade():
    db_instance = get_db()
    if request.method == "POST":
        trade_date = request.form.get("trade_date", "").strip()
        asset = request.form.get("asset", "").strip()
        pnl_str = request.form.get("pnl", "").strip()
        charges_str = request.form.get("charges", "").strip()
        comment = request.form.get("comment", "").strip()
        if not asset:
            flash("Please enter the asset traded.")
            return redirect(url_for("record_trade"))
        try:
            pnl = float(pnl_str)
        except ValueError:
            flash("Please enter a valid PnL amount.")
            return redirect(url_for("record_trade"))
        try:
            charges = float(charges_str)
        except ValueError:
            flash("Please enter a valid charges amount.")
            return redirect(url_for("record_trade"))
        net_pnl = pnl - charges
        commission = 0.3 * net_pnl if net_pnl > 0 else 0.0
        net_profit_after_commission = net_pnl - commission
        db_instance.add_trade(trade_date, asset, pnl, charges, commission, net_pnl, net_profit_after_commission, comment)
        # Distribute net profit among contributors proportionally.
        contributors = db_instance.get_all_contributors()
        total_eligible = 0.0
        eligible_dict = {}
        for row in contributors:
            cid = row["id"]
            eligible = db_instance.get_eligible_balance(cid, trade_date)
            eligible_dict[cid] = eligible
            total_eligible += eligible
        if total_eligible <= 0:
            flash("No eligible funds available as of the trade date.")
            return redirect(url_for("record_trade"))
        for cid, eligible in eligible_dict.items():
            share = (eligible / total_eligible) * net_profit_after_commission
            allocated_charges = (eligible / total_eligible) * charges
            db_instance.add_transaction(cid, trade_date, "trade", share, asset, allocated_charges, comment)
        flash(f"Trade recorded on {trade_date} for asset '{asset}'. Commission: Rs {commission:.2f}, Net profit distributed: Rs {net_profit_after_commission:.2f}.")
        return redirect(url_for("record_trade"))
    return render_template("record_trade.html")

# Withdraw Money (admin only)
@app.route("/withdraw_money", methods=["GET", "POST"])
@login_required
@admin_required
def withdraw_money():
    db_instance = get_db()
    if request.method == "POST":
        withdraw_date = request.form.get("withdraw_date", "").strip()
        amt_str = request.form.get("amount", "").strip()
        comment = request.form.get("comment", "").strip()
        try:
            withdraw_amt = float(amt_str)
            if withdraw_amt <= 0:
                raise ValueError
        except ValueError:
            flash("Enter a valid withdrawal amount greater than 0.")
            return redirect(url_for("withdraw_money"))
        total_fund = db_instance.get_total_fund(withdraw_date)
        if total_fund <= 0:
            flash("No funds available for withdrawal.")
            return redirect(url_for("withdraw_money"))
        contributors = db_instance.get_all_contributors()
        breakdown = ""
        for row in contributors:
            cid = row["id"]
            eligible = db_instance.get_eligible_balance(cid, withdraw_date)
            share = (eligible / total_fund) * withdraw_amt if total_fund > 0 else 0
            db_instance.add_transaction(cid, withdraw_date, "withdrawal", -share, "", 0.0, comment)
            breakdown += f"{row['name']}: Rs {share:.2f}\n"
        flash(f"Withdrawal on {withdraw_date} for Rs {withdraw_amt:.2f} processed.\nBreakdown:\n{breakdown}")
        return redirect(url_for("withdraw_money"))
    return render_template("withdraw_money.html")

# Manage Withdrawal Requests (admin only)
@app.route("/manage_withdrawal_requests")
@login_required
@admin_required
def manage_withdrawal_requests():
    db_instance = get_db()
    requests_list = db_instance.get_withdrawal_requests(status="pending")
    reqs = []
    for req in requests_list:
        contrib = db_instance.get_contributor_by_id(req["contributor_id"])
        reqs.append({
            "id": req["id"],
            "contributor": contrib["name"] if contrib else "Unknown",
            "request_date": req["request_date"],
            "amount": req["amount"],
            "comment": req["comment"],
            "status": req["status"]
        })
    return render_template("manage_withdrawal_requests.html", requests=reqs)

# Approve Withdrawal (admin only)
@app.route("/approve_withdrawal/<int:req_id>", methods=["GET", "POST"])
@login_required
@admin_required
def approve_withdrawal(req_id):
    db_instance = get_db()
    if request.method == "POST":
        admin_comment = request.form.get("admin_comment", "").strip()
        approved_date = date.today().strftime('%Y-%m-%d')
        db_instance.update_withdrawal_request(req_id, "approved", approved_date, admin_comment)
        req = None
        for r in db_instance.get_withdrawal_requests():
            if r["id"] == req_id:
                req = r
                break
        if req:
            db_instance.add_transaction(req["contributor_id"], approved_date, "withdrawal", -req["amount"], "", 0.0, "Withdrawal Approved")
        flash("Withdrawal request approved.")
        return redirect(url_for("manage_withdrawal_requests"))
    return render_template("approve_withdrawal.html", req_id=req_id)

# Reject Withdrawal (admin only)
@app.route("/reject_withdrawal/<int:req_id>", methods=["GET", "POST"])
@login_required
@admin_required
def reject_withdrawal(req_id):
    db_instance = get_db()
    if request.method == "POST":
        admin_comment = request.form.get("admin_comment", "").strip()
        approved_date = date.today().strftime('%Y-%m-%d')
        db_instance.update_withdrawal_request(req_id, "rejected", approved_date, admin_comment)
        flash("Withdrawal request rejected.")
        return redirect(url_for("manage_withdrawal_requests"))
    return render_template("reject_withdrawal.html", req_id=req_id)

# Request Withdrawal (non-admin only)
@app.route("/request_withdrawal", methods=["GET", "POST"])
@login_required
def request_withdrawal():
    db_instance = get_db()
    if session.get("role") == "admin":
        flash("Admins cannot request withdrawals.")
        return redirect(url_for("dashboard"))
    contrib = db_instance.get_contributor_by_login(session.get("username"))
    if request.method == "POST":
        req_date = request.form.get("request_date", "").strip()
        amt_str = request.form.get("amount", "").strip()
        comment = request.form.get("comment", "").strip()
        try:
            amount = float(amt_str)
            if amount <= 0:
                raise ValueError
        except ValueError:
            flash("Enter a valid withdrawal amount greater than 0.")
            return redirect(url_for("request_withdrawal"))
        db_instance.add_withdrawal_request(contrib["id"], req_date, amount, comment)
        flash(f"Your withdrawal request for Rs {amount:.2f} on {req_date} has been submitted and is pending approval.")
        return redirect(url_for("request_withdrawal"))
    return render_template("request_withdrawal.html")

# Notifications (non-admin only)
@app.route("/notifications")
@login_required
def notifications():
    db_instance = get_db()
    if session.get("role") == "admin":
        flash("Admins do not have notifications.")
        return redirect(url_for("dashboard"))
    contrib = db_instance.get_contributor_by_login(session.get("username"))
    reqs = db_instance.get_withdrawal_requests_for_contributor(contrib["id"])
    return render_template("notifications.html", requests=reqs)

# Detailed Summary
@app.route("/detailed_summary")
@login_required
def detailed_summary():
    db_instance = get_db()
    if session.get("role") == "admin":
        contributors = db_instance.get_all_contributors()
    else:
        contrib = db_instance.get_contributor_by_login(session.get("username"))
        contributors = [contrib] if contrib else []
    summaries = []
    for contrib in contributors:
        txns = db_instance.get_transactions_for_contributor(contrib["id"])
        running_total = 0.0
        txn_list = []
        for txn in txns:
            running_total += txn["amount"]
            txn_list.append({
                "date": txn["date"],
                "type": txn["type"],
                "asset": txn["asset"],
                "amount": f"{txn['amount']:.2f}",
                "allocated_charges": f"{txn['allocated_charges']:.2f}",
                "comment": txn["comment"],
                "running_total": f"{running_total:.2f}"
            })
        current_balance = running_total
        total_fund = db_instance.get_total_fund(date.today().strftime('%Y-%m-%d'))
        portfolio_pct = (current_balance / total_fund * 100) if total_fund > 0 else 0.0
        summaries.append({
            "name": contrib["name"],
            "current_balance": f"{current_balance:.2f}",
            "portfolio_pct": f"{portfolio_pct:.2f}",
            "transactions": txn_list
        })
    return render_template("detailed_summary.html", summaries=summaries)

# Trade History
@app.route("/trade_history")
@login_required
def trade_history():
    db_instance = get_db()
    role = session.get("role")
    if role == "admin":
        trades = db_instance.get_all_trades()
    else:
        contrib = db_instance.get_contributor_by_login(session.get("username"))
        all_trades = db_instance.get_all_trades()
        my_txns = db_instance.get_transactions_for_contributor(contrib["id"])
        my_trade_keys = {(txn["date"], txn["asset"]) for txn in my_txns if txn["type"]=="trade"}
        trades = [trade for trade in all_trades if (trade["trade_date"], trade["asset"]) in my_trade_keys]
    formatted_trades = []
    for trade in trades:
        formatted_trades.append({
            "id": trade["id"],
            "trade_date": trade["trade_date"],
            "asset": trade["asset"],
            "pnl": f"{trade['pnl']:.2f}",
            "charges": f"{trade['charges']:.2f}",
            "net_pnl": f"{trade['net_pnl']:.2f}",
            "commission": f"{trade['commission']:.2f}",
            "net_profit_after_commission": f"{trade['net_profit_after_commission']:.2f}",
            "comment": trade["comment"]
        })
    return render_template("trade_history.html", trades=formatted_trades, role=role)

# Export Transactions CSV
@app.route("/export_transactions")
@login_required
def export_transactions():
    db_instance = get_db()
    transactions = db_instance.get_all_transactions()
    if not transactions:
        flash("No transactions to export.")
        return redirect(url_for("dashboard"))
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID", "Contributor ID", "Date", "Type", "Amount", "Asset", "Allocated Charges", "Comment"])
    for txn in transactions:
        cw.writerow([txn["id"], txn["contributor_id"], txn["date"], txn["type"],
                     txn["amount"], txn["asset"], txn["allocated_charges"], txn["comment"]])
    return make_csv_response(si.getvalue(), "transactions.csv")

# Export Trades CSV
@app.route("/export_trades")
@login_required
def export_trades():
    db_instance = get_db()
    trades = db_instance.get_all_trades()
    if not trades:
        flash("No trades to export.")
        return redirect(url_for("dashboard"))
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID", "Trade Date", "Asset", "PnL", "Charges", "Commission", "Net PnL", "Net Profit After Commission", "Comment"])
    for trade in trades:
        cw.writerow([trade["id"], trade["trade_date"], trade["asset"], trade["pnl"],
                     trade["charges"], trade["commission"], trade["net_pnl"],
                     trade["net_profit_after_commission"], trade["comment"]])
    return make_csv_response(si.getvalue(), "trades.csv")

def make_csv_response(csv_data, filename):
    output = Response(csv_data, mimetype="text/csv")
    output.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return output

# Manage Contributors (admin only)
@app.route("/manage_contributors")
@login_required
@admin_required
def manage_contributors():
    db_instance = get_db()
    contributors = db_instance.get_all_contributors()
    return render_template("manage_contributors.html", contributors=contributors)

# Edit Contributor (admin only)
@app.route("/edit_contributor/<int:contrib_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_contributor(contrib_id):
    db_instance = get_db()
    contributor = db_instance.get_contributor_by_id(contrib_id)
    if not contributor:
        flash("Contributor not found.")
        return redirect(url_for("manage_contributors"))
    if request.method == "POST":
        new_name = request.form.get("name", "").strip()
        new_type = request.form.get("ctype", "").strip()
        if not new_name:
            flash("Name cannot be empty.")
            return redirect(url_for("edit_contributor", contrib_id=contrib_id))
        db_instance.update_contributor(contrib_id, new_name, new_type)
        flash("Contributor updated successfully.")
        return redirect(url_for("manage_contributors"))
    return render_template("edit_contributor.html", contributor=contributor)

# Assign Credentials (admin only)
@app.route("/assign_credentials/<int:contrib_id>", methods=["GET", "POST"])
@login_required
@admin_required
def assign_credentials(contrib_id):
    db_instance = get_db()
    contributor = db_instance.get_contributor_by_id(contrib_id)
    if not contributor:
        flash("Contributor not found.")
        return redirect(url_for("manage_contributors"))
    if contributor["login_username"]:
        flash("This contributor already has credentials assigned.")
        return redirect(url_for("manage_contributors"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            flash("Please enter both username and password.")
            return redirect(url_for("assign_credentials", contrib_id=contrib_id))
        db_instance.update_contributor_login(contrib_id, username)
        try:
            db_instance.add_user(username, password, role="user")
        except Exception as e:
            flash(str(e))
            return redirect(url_for("assign_credentials", contrib_id=contrib_id))
        flash("Credentials assigned successfully.")
        return redirect(url_for("manage_contributors"))
    return render_template("assign_credentials.html", contributor=contributor)

# Manage Users (admin only)
@app.route("/manage_users")
@login_required
@admin_required
def manage_users():
    db_instance = get_db()
    users = db_instance.get_all_users()
    return render_template("manage_users.html", users=users)

# Edit User (admin only)
@app.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_user(user_id):
    db_instance = get_db()
    users = db_instance.get_all_users()
    user = None
    for u in users:
        if u["id"] == user_id:
            user = u
            break
    if not user:
        flash("User not found.")
        return redirect(url_for("manage_users"))
    if request.method == "POST":
        new_username = request.form.get("username", "").strip()
        new_password = request.form.get("password", "").strip()
        new_role = request.form.get("role", "").strip()
        if not new_username:
            flash("Username cannot be empty.")
            return redirect(url_for("edit_user", user_id=user_id))
        if not new_password:
            flash("Please enter a new password.")
            return redirect(url_for("edit_user", user_id=user_id))
        db_instance.update_user(user_id, new_username, new_password, new_role)
        flash("User updated successfully.")
        return redirect(url_for("manage_users"))
    return render_template("edit_user.html", user=user)

# Edit Trade (admin only)
@app.route("/edit_trade/<int:trade_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_trade(trade_id):
    db_instance = get_db()
    trades = db_instance.get_all_trades()
    trade = None
    for t in trades:
        if t["id"] == trade_id:
            trade = t
            break
    if not trade:
        flash("Trade not found.")
        return redirect(url_for("trade_history"))
    if request.method == "POST":
        trade_date = request.form.get("trade_date", "").strip()
        asset = request.form.get("asset", "").strip()
        try:
            pnl = float(request.form.get("pnl", "").strip())
            charges = float(request.form.get("charges", "").strip())
        except ValueError:
            flash("Invalid PnL or Charges.")
            return redirect(url_for("edit_trade", trade_id=trade_id))
        comment = request.form.get("comment", "").strip()
        net_pnl = pnl - charges
        commission = 0.3 * net_pnl if net_pnl > 0 else 0.0
        net_profit_after_commission = net_pnl - commission
        db_instance.update_trade(trade_id, trade_date, asset, pnl, charges, commission, net_pnl, net_profit_after_commission, comment)
        flash("Trade updated successfully.")
        return redirect(url_for("trade_history"))
    return render_template("edit_trade.html", trade=trade)

# Edit Transaction (admin only)
@app.route("/edit_transaction/<int:txn_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_transaction(txn_id):
    db_instance = get_db()
    txns = db_instance.get_all_transactions()
    txn = None
    for t in txns:
        if t["id"] == txn_id:
            txn = t
            break
    if not txn:
        flash("Transaction not found.")
        return redirect(url_for("detailed_summary"))
    if request.method == "POST":
        date_str = request.form.get("date", "").strip()
        txn_type = request.form.get("type", "").strip()
        try:
            amount = float(request.form.get("amount", "").strip())
            allocated_charges = float(request.form.get("allocated_charges", "").strip())
        except ValueError:
            flash("Invalid amount or charges.")
            return redirect(url_for("edit_transaction", txn_id=txn_id))
        asset = request.form.get("asset", "").strip()
        comment = request.form.get("comment", "").strip()
        db_instance.update_transaction(txn_id, txn["contributor_id"], date_str, txn_type, amount, asset, allocated_charges, comment)
        flash("Transaction updated successfully.")
        return redirect(url_for("detailed_summary"))
    return render_template("edit_transaction.html", txn=txn)

# ----------------------------
# Run the App
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)
