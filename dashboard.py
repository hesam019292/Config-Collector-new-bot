# -*- coding: utf-8 -*-
"""
پنل تحت وب ادمین — بر پایه‌ی Flask، برای دیپلوی روی Railway کنار فایل اصلی
بات (app.py).

طبق درخواست صریح ادمین (نسخه v7.0):
  - این پنل اکنون کاملاً و فقط مخصوص ادمین است. هیچ صفحه یا API عمومی/کاربری
    (لینک ساب، صفحه‌ی وضعیت عمومی) در آن وجود ندارد — همه چیز پشت توکن ادمین
    است.
  - هیچ ارجاعی به سیستم Real Ping Tester یا آرشیو کانفیگ باقی نمانده؛ هر دو
    از app.py هم حذف شده‌اند.

معماری (چرا این‌طور طراحی شده):
  روی Railway، دو پروسه‌ی جدا در یک سرویس واحد می‌توانند هم‌زمان اجرا شوند و
  همان فایل‌سیستم محلی (و درنتیجه همان فایل SQLite) را به اشتراک بگذارند —
  اما دو سرویس جدا معمولاً فایل‌سیستم مشترک ندارند مگر با Railway Volume
  (پیچیدگی و هزینه‌ی اضافه). چون بات از aiosqlite با mode=WAL استفاده می‌کند،
  این پروسه‌ی دوم می‌تواند هم‌زمان و امن از همان فایل دیتابیس بخواند بدون
  قفل‌کردن نویسنده‌ی اصلی (بات). از طریق start.sh هر دو با هم اجرا می‌شوند.

  دیتابیس فقط خوانده می‌شود (اتصال سراسری mode=ro در سطح فایل‌سیستم)؛ تنها
  استثنا عملیات نوشتنی صریح ادمین (فعال/غیرفعال‌کردن منبع) که هر کدام یک
  اتصال کوتاه‌مدت جداگانه‌ی read-write باز می‌کنند.

امنیت:
  - کل پنل با یک توکن محافظت می‌شود (env var ADMIN_PANEL_TOKEN). اگر این
    متغیر ست نشده باشد، پنل به‌طور کامل قفل می‌ماند (fail-closed) — هیچ
    صفحه یا API ای، حتی به‌صورت تصادفی، در دسترس نخواهد بود.
"""
from __future__ import annotations

import hmac
import math
import os
import sqlite3
from datetime import datetime, timezone

from flask import Flask, Response, abort, g, jsonify, render_template, request

# ══════════════════════════════════════════════════════════════════════════
# تنظیمات
# ══════════════════════════════════════════════════════════════════════════
DB_PATH           = os.environ.get("DB_PATH", "bot_database.db")
ADMIN_PANEL_TOKEN = os.environ.get("ADMIN_PANEL_TOKEN", "")
PORT              = int(os.environ.get("WEBDASH_PORT", os.environ.get("PORT", "8080")))

app = Flask(__name__, template_folder="templates", static_folder="static")

# رفع باگ #16 (ناهماهنگی نقشه‌ی کشورها در پنل وب): این دیکشنری قبلاً فقط
# ۳۰ کشور اولیه‌ی COUNTRY_MAP در app.py را داشت. وقتی بعداً کشورهای جدید
# (خاورمیانه، آسیا، اقیانوسیه، آمریکای لاتین، آفریقا) به COUNTRY_MAP در بات
# اضافه شدند، این دیکشنری هرگز به‌روزرسانی نشد — پنل وب برای آن کد کشورها
# مقدار "Unspecified" نمایش می‌داد، حتی وقتی خودِ بات به‌درستی نام و پرچم
# کامل را می‌شناخت. حالا این دیکشنری دقیقاً با COUNTRY_MAP در app.py
# هماهنگ نگه داشته شده (نام انگلیسی هر کشور) تا این دو منبع دیگر واگرا
# نشوند. اگر در آینده کشور جدیدی به COUNTRY_MAP در app.py اضافه شد، باید
# همان کد و نام انگلیسی این‌جا هم اضافه شود.
COUNTRY_NAMES = {
    "de": "Germany", "nl": "Netherlands", "fi": "Finland", "se": "Sweden",
    "fr": "France", "gb": "United Kingdom", "us": "United States", "ca": "Canada",
    "jp": "Japan", "sg": "Singapore", "ru": "Russia", "ua": "Ukraine",
    "br": "Brazil", "au": "Australia", "in": "India", "kr": "South Korea",
    "tr": "Turkey", "at": "Austria", "ch": "Switzerland", "pl": "Poland",
    "cz": "Czechia", "ro": "Romania", "hu": "Hungary", "lt": "Lithuania",
    "lv": "Latvia", "ee": "Estonia", "no": "Norway", "dk": "Denmark",
    "es": "Spain", "it": "Italy",
    # ── گسترش جدید: خاورمیانه، آسیا، اقیانوسیه، آمریکای لاتین، آفریقا ──────
    "ae": "United Arab Emirates", "sa": "Saudi Arabia",
    "il": "Israel", "eg": "Egypt",
    "hk": "Hong Kong", "tw": "Taiwan",
    "my": "Malaysia", "th": "Thailand",
    "vn": "Vietnam", "id": "Indonesia",
    "ph": "Philippines", "cn": "China",
    "za": "South Africa", "mx": "Mexico",
    "ar": "Argentina", "cl": "Chile",
    "co": "Colombia", "ie": "Ireland",
    "pt": "Portugal", "be": "Belgium",
    "gr": "Greece", "bg": "Bulgaria",
    "hr": "Croatia", "sk": "Slovakia",
    "si": "Slovenia", "is": "Iceland",
    "lu": "Luxembourg", "md": "Moldova",
    "rs": "Serbia", "kz": "Kazakhstan",
    "ge": "Georgia", "am": "Armenia",
    "az": "Azerbaijan",
    "ALL": "Unspecified",
}


# ══════════════════════════════════════════════════════════════════════════
# دسترسی به دیتابیس
# ══════════════════════════════════════════════════════════════════════════
def get_db() -> sqlite3.Connection:
    """
    یک اتصال read-only در سطح فایل‌سیستم (mode=ro) برای هر request — یعنی
    حتی یک باگ در این پنل هم فیزیکاً نمی‌تواند چیزی در دیتابیس بات را
    خراب کند. عملیات نوشتنی صریح (پایین‌تر) از اتصال جدای خودشان استفاده
    می‌کنند.
    """
    if "db" not in g:
        uri = f"file:{DB_PATH}?mode=ro"
        g.db = sqlite3.connect(uri, uri=True, timeout=5)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def q(sql: str, params: tuple = ()) -> list:
    """اجرای یک SELECT؛ اگر دیتابیس هنوز وجود ندارد (اولین لحظه‌ی استارت بات)، خالی برمی‌گرداند نه کرش."""
    try:
        return get_db().execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def q_one(sql: str, params: tuple = (), key: str = "c", default=0):
    rows = q(sql, params)
    if not rows:
        return default
    val = rows[0][key]
    return val if val is not None else default


def write(sql: str, params: tuple = ()) -> None:
    """
    برای عملیات نوشتنی محدود ادمین (فعال/غیرفعال‌کردن منبع و غیره) — یک
    اتصال read-write کوتاه‌مدت جداگانه باز می‌کند. WAL این هم‌زیستی چند
    نویسنده را با بات اصلی امن می‌کند.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════════
# احراز هویت
# ══════════════════════════════════════════════════════════════════════════
def _admin_authed() -> bool:
    if not ADMIN_PANEL_TOKEN:
        return False  # fail-closed: بدون توکن، هیچ‌کس (حتی ادمین) دسترسی ندارد
    supplied = request.args.get("token") or request.headers.get("X-Admin-Token") or ""
    return hmac.compare_digest(supplied, ADMIN_PANEL_TOKEN)


def require_admin(fn):
    def wrapper(*a, **kw):
        if not _admin_authed():
            abort(403)
        return fn(*a, **kw)
    wrapper.__name__ = fn.__name__
    return wrapper


# ══════════════════════════════════════════════════════════════════════════
# صفحات
# ══════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    # هیچ صفحه‌ی عمومی وجود ندارد — طبق درخواست ادمین، فقط و فقط پنل ادمین.
    if _admin_authed():
        return render_template("admin.html", token=request.args.get("token", ""))
    return render_template("admin_login.html"), 403


@app.route("/admin")
def admin_page():
    if not _admin_authed():
        return render_template("admin_login.html"), 403
    return render_template("admin.html", token=request.args.get("token", ""))


# ══════════════════════════════════════════════════════════════════════════
# API — نمای کلی
# ══════════════════════════════════════════════════════════════════════════
@app.route("/api/admin/overview")
@require_admin
def api_overview():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_row = q(
        "SELECT SUM(requests_count) s, SUM(configs_received) g FROM daily_usage WHERE date=?",
        (today,),
    )
    today_reqs = today_row[0]["s"] if today_row and today_row[0]["s"] is not None else 0
    today_cfgs = today_row[0]["g"] if today_row and today_row[0]["g"] is not None else 0

    return jsonify({
        "sources_total":   q_one("SELECT COUNT(*) c FROM sources"),
        "sources_enabled": q_one("SELECT COUNT(*) c FROM sources WHERE enabled=1"),
        "sources_failing": q_one("SELECT COUNT(*) c FROM sources WHERE fail_count > 0"),
        "users_total":     q_one("SELECT COUNT(*) c FROM prefs"),
        "vip_total":       q_one("SELECT COUNT(*) c FROM prefs WHERE is_vip=1"),
        "banned_total":    q_one("SELECT COUNT(*) c FROM banned_users"),
        "blacklisted_ips": q_one("SELECT COUNT(*) c FROM ip_blacklist"),
        "feedback_total":  q_one("SELECT COUNT(*) c FROM user_feedback"),
        "rules_total":     q_one("SELECT COUNT(*) c FROM rules"),
        "rules_enabled":   q_one("SELECT COUNT(*) c FROM rules WHERE enabled=1"),
        "github_sources_found": q_one("SELECT COUNT(*) c FROM github_sources"),
        "today_requests":  today_reqs,
        "today_configs":   today_cfgs,
    })


@app.route("/api/admin/sources")
@require_admin
def api_sources():
    page     = max(1, int(request.args.get("page", 1)))
    per_page = 25
    total    = q_one("SELECT COUNT(*) c FROM sources")
    rows = q(
        """SELECT id, url, enabled, fail_count, last_fail_time, datacenter, found_via
           FROM sources ORDER BY id DESC LIMIT ? OFFSET ?""",
        (per_page, (page - 1) * per_page),
    )
    return jsonify({
        "total": total, "page": page, "pages": max(1, math.ceil(total / per_page)),
        "items": [dict(r) for r in rows],
    })


@app.route("/api/admin/sources/<int:source_id>/toggle", methods=["POST"])
@require_admin
def api_toggle_source(source_id: int):
    row = q("SELECT enabled FROM sources WHERE id=?", (source_id,))
    if not row:
        return jsonify({"ok": False, "error": "not found"}), 404
    new_val = 0 if row[0]["enabled"] else 1
    write("UPDATE sources SET enabled=? WHERE id=?", (new_val, source_id))
    return jsonify({"ok": True, "enabled": bool(new_val)})


@app.route("/api/admin/users")
@require_admin
def api_users():
    # رفع باگ #24 (عدم نمایش وضعیت داخلی کاربر در پنل): ستون user_state
    # (مثلاً وقتی کاربر منتظر ورود تعداد کانفیگ یا عبارت جستجو است) قبلاً
    # اصلاً در این کوئری انتخاب نمی‌شد، پس هیچ‌وقت هم در پاسخ API و هم در
    # جدول کاربران پنل وب دیده نمی‌شد — با اینکه برای دیباگ رفتار کاربران
    # (مثلاً وقتی یک کاربر گزارش می‌دهد «بات گیر کرده») بسیار مفید است.
    page     = max(1, int(request.args.get("page", 1)))
    per_page = 25
    search   = (request.args.get("search") or "").strip()
    if search:
        like  = f"%{search}%"
        total = q_one(
            "SELECT COUNT(*) c FROM prefs WHERE username LIKE ? OR first_name LIKE ? OR CAST(user_id AS TEXT) LIKE ?",
            (like, like, like),
        )
        rows = q(
            """SELECT user_id, username, first_name, is_vip, total_downloads, last_seen, language, user_state
               FROM prefs WHERE username LIKE ? OR first_name LIKE ? OR CAST(user_id AS TEXT) LIKE ?
               ORDER BY last_seen DESC LIMIT ? OFFSET ?""",
            (like, like, like, per_page, (page - 1) * per_page),
        )
    else:
        total = q_one("SELECT COUNT(*) c FROM prefs")
        rows = q(
            """SELECT user_id, username, first_name, is_vip, total_downloads, last_seen, language, user_state
               FROM prefs ORDER BY last_seen DESC LIMIT ? OFFSET ?""",
            (per_page, (page - 1) * per_page),
        )
    return jsonify({
        "total": total, "page": page, "pages": max(1, math.ceil(total / per_page)),
        "items": [dict(r) for r in rows],
    })


@app.route("/api/admin/banned")
@require_admin
def api_banned():
    rows = q("SELECT user_id, banned_at, reason FROM banned_users ORDER BY banned_at DESC LIMIT 200")
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/api/admin/blacklist")
@require_admin
def api_blacklist():
    rows = q("SELECT ip, reason, added_at FROM ip_blacklist ORDER BY added_at DESC LIMIT 200")
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/api/admin/feedback")
@require_admin
def api_feedback():
    # رفع باگ #23 (عدم امکان جستجو در لاگ‌ها و بازخوردها): قبلاً این
    # endpoint همیشه فقط ۱۰۰ رکورد آخر را برمی‌گرداند، بدون هیچ راهی برای
    # فیلتر کردن بر اساس user_id، config_hash یا متن reason. حالا یک پارامتر
    # اختیاری q می‌پذیرد که روی این سه فیلد جستجو می‌کند (پارامترایز‌شده،
    # بدون خطر SQL injection).
    search = (request.args.get("q") or "").strip()
    if search:
        like = f"%{search}%"
        rows = q(
            """SELECT id, user_id, config_hash, reason, timestamp
               FROM user_feedback
               WHERE CAST(user_id AS TEXT) LIKE ? OR config_hash LIKE ? OR reason LIKE ?
               ORDER BY timestamp DESC LIMIT 100""",
            (like, like, like))
    else:
        rows = q(
            """SELECT id, user_id, config_hash, reason, timestamp
               FROM user_feedback ORDER BY timestamp DESC LIMIT 100""")
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/api/admin/rules")
@require_admin
def api_rules():
    rows = q(
        """SELECT id, name, condition, action, enabled, last_triggered, created_at
           FROM rules ORDER BY id DESC""")
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/api/admin/github_sources")
@require_admin
def api_github_sources():
    rows = q(
        """SELECT id, url, repo, stars, found_at, notified
           FROM github_sources ORDER BY found_at DESC LIMIT 100""")
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/api/admin/logs")
@require_admin
def api_logs():
    # ستون واقعی این جدول در app.py «source» است، نه «context» — رفع یک
    # ناهماهنگی که در نسخه‌ی قبلی این فایل وجود داشت.
    # رفع باگ #23: پارامتر اختیاری q برای جستجوی متنی در level/source/message.
    search = (request.args.get("q") or "").strip()
    if search:
        like = f"%{search}%"
        rows = q(
            """SELECT timestamp, level, source, message FROM system_logs
               WHERE level LIKE ? OR source LIKE ? OR message LIKE ?
               ORDER BY timestamp DESC LIMIT 150""",
            (like, like, like))
    else:
        rows = q(
            "SELECT timestamp, level, source, message FROM system_logs ORDER BY timestamp DESC LIMIT 150")
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/api/admin/export_configs")
@require_admin
def api_export_configs():
    """
    خروجی کامل کانفیگ‌های خام کش (این‌ها در دیتابیس ذخیره نمی‌شوند — فقط در
    حافظه‌ی پروسه‌ی بات هستند)، پس این پنل نمی‌تواند مستقیم به آن‌ها دسترسی
    داشته باشد. برای دریافت این فایل از دستور /export داخل خودِ بات
    استفاده کنید.
    """
    return jsonify({
        "ok": False,
        "note": ("کش کانفیگ‌های خام فقط در حافظه‌ی پروسه‌ی بات نگه داشته می‌شود، "
                  "نه در دیتابیس — از دستور /export یا دکمه‌ی «Export کانفیگ» "
                  "در پنل ادمین خودِ بات استفاده کنید."),
    }), 501


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
