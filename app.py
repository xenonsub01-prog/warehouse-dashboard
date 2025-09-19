
import os, json, time, base64, hmac, hashlib, re, secrets, string
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus

import pandas as pd
import streamlit as st

# ---------- Helpers ----------
def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_token(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    to_sign = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), to_sign, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def verify_token(token: str, secret: str) -> dict | None:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        to_sign = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(secret.encode(), to_sign, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_sig, b64url_decode(sig_b64)):
            return None
        payload = json.loads(b64url_decode(payload_b64))
        now = int(time.time())
        if "exp" in payload and now > int(payload["exp"]):
            return None
        return payload
    except Exception:
        return None

def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")
    return s.lower() or "client"

def random_code(n=10):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(n))

# ---------- Config ----------
SECRET = os.getenv("DEMO_SECRET", "CHANGE_ME_IN_ENV_FOR_PROD")
OWNER_KEY = os.getenv("OWNER_KEY", "")  # if provided, ?admin=OWNER_KEY bypasses token
DATA_PATH = os.getenv("DATA_PATH", "data/orders.csv")
LOG_PATH = os.getenv("LOG_PATH", "data/log.csv")
LOOKUPS_PATH = os.getenv("LOOKUPS_PATH", "data/lookups.csv")
TOKENS_DIR = os.getenv("TOKENS_DIR", "tokens")
CODES_PATH = os.path.join(TOKENS_DIR, "codes.json")
CONFIG_PATH = os.getenv("CONFIG_PATH", "config.json")

st.set_page_config(page_title="Warehouse Dashboard Demo", layout="wide")

# Load/save config
def load_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def save_config(cfg: dict):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

cfg = load_config()
default_base_url = cfg.get("base_url", os.getenv("BASE_URL", "http://localhost:8501/"))

# ---------- Resolve incoming auth (token, code, or admin) ----------
qs = st.query_params
token = qs.get("token", None)
code = qs.get("c", None)
admin_key = qs.get("admin", None)

# Owner bypass
payload = None
if OWNER_KEY and admin_key == OWNER_KEY:
    far_future = int((datetime.now(tz=timezone.utc) + timedelta(days=365*5)).timestamp())
    payload = {"company": "Owner", "user": "owner", "role": "owner", "exp": far_future}

# Code → token
if not payload and code:
    try:
        with open(CODES_PATH, "r", encoding="utf-8") as f:
            codes = json.load(f)
        token = codes.get(code)
    except Exception:
        token = None

# Token verify
if not payload and token:
    payload = verify_token(token, SECRET)

# Show Admin panel regardless; but gate main content if not authorized
with st.sidebar.expander("⚙️ Admin (Owner) — Token & Link", expanded=False):
    if OWNER_KEY:
        st.caption("Tip: open with ?admin=YOUR_OWNER_KEY to bypass token (owner mode).")
    base_url = st.text_input("Base URL (external)", value=default_base_url)
    company = st.text_input("Company name", value="Client Warehouse Co.")
    user_email = st.text_input("User email (optional)", value="demo-client@example.com")
    colA, colB = st.columns(2)
    unit = colA.selectbox("Expiry unit", ["hours", "days"], index=0)
    amount = colB.number_input("Expiry amount", min_value=1, max_value=365, value=24, step=1)
    role = st.selectbox("Role", ["viewer", "editor"], index=1)
    short_link = st.checkbox("Use short code link (?c=CODE)", value=True)

    if st.button("Generate Token & Link", use_container_width=True):
        cfg["base_url"] = base_url
        save_config(cfg)

        delta = timedelta(hours=amount) if unit == "hours" else timedelta(days=amount)
        exp = int((datetime.now(tz=timezone.utc) + delta).timestamp())
        payload_new = {"company": company, "user": user_email or "demo-client", "role": role, "exp": exp}
        token_new = sign_token(payload_new, SECRET)

        comp_qs = quote_plus(company)
        base_url_clean = base_url if base_url.endswith("/") else base_url + "/"

        os.makedirs(TOKENS_DIR, exist_ok=True)
        slug = slugify(company)
        # Save token file
        token_path = os.path.join(TOKENS_DIR, f"{slug}.txt")
        with open(token_path, "w", encoding="utf-8") as f:
            f.write(f"Company: {company}\nUser: {user_email}\nRole: {role}\nExpires: {datetime.fromtimestamp(exp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\nTOKEN: {token_new}\n")

        if short_link:
            # Map short code to token
            code_val = random_code(10)
            try:
                codes = {}
                if os.path.exists(CODES_PATH):
                    with open(CODES_PATH, "r", encoding="utf-8") as f:
                        codes = json.load(f)
                codes[code_val] = token_new
                with open(CODES_PATH, "w", encoding="utf-8") as f:
                    json.dump(codes, f)
            except Exception:
                pass
            url = f"{base_url_clean}?c={code_val}&company={comp_qs}"
            st.code(f"Short URL: {url}", language="text")
        else:
            url = f"{base_url_clean}?token={token_new}&company={comp_qs}"
            st.code(f"URL: {url}", language="text")

        st.success("Token & link generated!")
        st.code(f"TOKEN: {token_new}", language="text")
        with open(token_path, "rb") as f:
            st.download_button("Download token file", f, file_name=f"{slug}.txt", mime="text/plain")

# If not authorized, show info and stop
if not payload:
    st.error("Access denied. Invalid or expired token. Use Admin panel to generate a link or open with ?c=CODE or ?admin=OWNER_KEY.")
    st.stop()

# ---------- Main app (authorized) ----------
company = qs.get("company", payload.get("company", "Client Warehouse Co."))
role = payload.get("role", "viewer")

st.sidebar.success(f"Authorized: {role}")
exp_utc = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
st.sidebar.caption(f"Token expires: {exp_utc}")
st.title(f"📦 {company} — Warehouse Orders (Demo)")

@st.cache_data(ttl=10)
def load_orders():
    df = pd.read_csv(DATA_PATH, dtype={"OrderID": str})
    if "OrderDate" in df.columns:
        df["OrderDate"] = pd.to_datetime(df["OrderDate"], errors="coerce")
    return df

@st.cache_data(ttl=10)
def load_lookups():
    return pd.read_csv(LOOKUPS_PATH)

def save_orders(df: pd.DataFrame):
    df.to_csv(DATA_PATH, index=False)

def append_log(row: dict):
    import csv
    exists = os.path.exists(LOG_PATH)
    with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["Timestamp","User","Warehouse","OrderID","FromStatus","ToStatus","FromInvoice","ToInvoice"])
        if not exists:
            w.writeheader()
        w.writerow(row)

df = load_orders()
lk = load_lookups()
statuses = lk[lk["Type"]=="Status"]["Value"].tolist()
warehouses = sorted(df["Warehouse"].dropna().unique().tolist())

def kpi_block(sub_df: pd.DataFrame):
    col1, col2, col3, col4 = st.columns(4)
    open_cnt = int((sub_df["Status"] != "Invoiced").sum())
    if "OrderDate" in sub_df.columns:
        days = (pd.Timestamp("today").normalize() - sub_df["OrderDate"]).dt.days
        overdue_cnt = int(((days > 7) & (sub_df["Status"] != "Invoiced")).sum())
        today_cnt = int((sub_df["OrderDate"].dt.date == pd.Timestamp("today").date()).sum())
    else:
        overdue_cnt = 0
        today_cnt = 0
    invoiced_cnt = int((sub_df["Status"] == "Invoiced").sum())
    col1.metric("Open", open_cnt)
    col2.metric("Overdue (>7d)", overdue_cnt)
    col3.metric("Today", today_cnt)
    col4.metric("Invoiced", invoiced_cnt)

if not warehouses:
    st.info("No warehouses found in data.")
else:
    tabs = st.tabs(warehouses)
    for i, wh in enumerate(warehouses):
        with tabs[i]:
            sub = df[df["Warehouse"]==wh].copy()
            kpi_block(sub)
            st.subheader(f"{wh} Orders")
            st.dataframe(sub.sort_values("OrderDate", ascending=False), use_container_width=True, height=300)

            st.markdown("### Update Order")
            with st.form(f"update_form_{wh}"):
                order_ids = sub["OrderID"].tolist()
                if not order_ids:
                    st.info("No orders for this warehouse.")
                else:
                    order_id = st.selectbox("OrderID", order_ids, key=f"oid_{wh}")
                    current_status = sub.loc[sub['OrderID']==order_id, 'Status'].iloc[0] if order_id else statuses[0]
                    idx_stat = statuses.index(current_status) if current_status in statuses else 0
                    new_status = st.selectbox("New Status", statuses, index=idx_stat, key=f"st_{wh}")
                    current_inv = sub.loc[sub['OrderID']==order_id, 'InvoiceNo'].iloc[0] if order_id else ""
                    new_invoice = st.text_input("Invoice No (optional)", value=str(current_inv), key=f"inv_{wh}")
                    submitted = st.form_submit_button("Update", disabled=(role=="viewer"))
            if 'submitted' in locals() and submitted:
                idx = df.index[df["OrderID"]==order_id]
                if len(idx)==0:
                    st.error("OrderID not found in Master.")
                else:
                    i0 = idx[0]
                    old_status = df.at[i0, "Status"]
                    old_invoice = str(df.at[i0, "InvoiceNo"]) if not pd.isna(df.at[i0, "InvoiceNo"]) else ""
                    df.at[i0, "Status"] = new_status
                    df.at[i0, "InvoiceNo"] = new_invoice
                    df.at[i0, "UpdatedBy"] = payload.get("user", "demo-user")
                    df.at[i0, "UpdatedAt"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
                    save_orders(df)
                    append_log({
                        "Timestamp": datetime.utcnow().isoformat(timespec="seconds")+"Z",
                        "User": payload.get("user", "demo-user"),
                        "Warehouse": wh,
                        "OrderID": order_id,
                        "FromStatus": old_status,
                        "ToStatus": new_status,
                        "FromInvoice": old_invoice,
                        "ToInvoice": new_invoice,
                    })
                    st.success(f"Order {order_id} updated.")
                    st.cache_data.clear()

st.divider()
st.caption("Owner bypass (?admin=OWNER_KEY). Short links (?c=CODE). Master table + per-warehouse tabs + audit log.")
