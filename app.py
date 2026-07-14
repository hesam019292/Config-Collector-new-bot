#!/usr/bin/env python3
"""
Config Collector Bot v7.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
نسخه تولیدی ربات جمع‌آوری و توزیع کانفیگ‌های V2Ray/VPN — Railway.com
تمام پارامترها از طریق متغیرهای محیطی قابل تنظیم در Railway هستند.

[v7.0] تغییرات این نسخه (طبق درخواست صریح ادمین):
  • حذف کامل فیلتر کیفیت سلیقه‌ای (QualityFilter، HoneyPotDetector) — تنها
    اعتبارسنجی ساختاری URI و IPBlacklist مدیریتی باقی مانده‌اند.
  • حذف کامل سیستم آرشیو کانفیگ‌های حذف‌شده (بی‌نیاز شد چون فیلتر کیفیت
    حذف شد).
  • حذف کامل سیستم Real Ping Tester (Xray-core، تست SOCKS، جدول
    tested_configs، تمام دکمه‌ها و cron job های مرتبط) — بات دیگر پینگ
    نمی‌گیرد و کانفیگ‌ها مستقیماً از کش خام منابع تحویل داده می‌شوند.
  • CONFIG_BRAND دیگر مقدار پیش‌فرض هاردکد ندارد — کاملاً از طریق env var.
  • پنل تحت وب (dashboard.py) اکنون کاملاً و فقط مخصوص ادمین است — صفحه‌ی
    عمومی و لینک ساب اختصاصی کاربر هر دو حذف شدند.
  • فیلتر پروتکل تقویت شد: پشتیبانی از hysteria (v1)، ssr، socks، naive،
    snell — که قبلاً اصلاً استخراج نمی‌شدند.
  • فیلتر کشور به‌شدت تقویت شد: از ۲۹ به ۶۳ کشور، تشخیص با پرچم ایموجی +
    نام انگلیسی/فارسی + نام شهر + کد ISO با مرزبندی صحیح — بدون نیاز به
    GeoIP یا API خارجی.
  • جستجوی چندکلمه‌ای (AND روی کلمات) با پشتیبانی از نام انگلیسی کشورها.
  • رفع باگ حیاتی: منوی اصلی و نمایش کشور همیشه فارسی بودند صرف‌نظر از
    زبان انتخابی کاربر — اکنون کاملاً دوزبانه‌ی واقعی.
  • بات اکنون در گروه‌ها هم به‌درستی کار می‌کند — فقط وقتی کاربر دستور
    می‌زند یا بات را منشن/ریپلای می‌کند پاسخ می‌دهد.
[ویژگی‌های نسخه‌های قبلی که هم‌چنان فعال هستند]:
  • سیستم VIP کاربران (bypass محدودیت روزانه)
  • جستجوی پیشرفته کانفیگ برای کاربران (cooldown 30s)
  • پنل ادمین شیشه‌ای حرفه‌ای
  • Dedup پیشرفته بر اساس fingerprint (UUID/host/port)
  • Blacklist IP برای کانفیگ‌های مخرب
  • سیستم Abuse Detection با امتیازدهی ریسک
  • Smart Notification (کش کم، RAM بالا، خطای زیاد)
  • Broadcast حرفه‌ای (فعال، غیرفعال، VIP، همه)
  • سیستم Feedback کانفیگ توسط کاربران
  • Analytics کاربران فعال/غیرفعال
  • پروفایل کاربر (محبوب‌ترین کشور، پروتکل، آمار)
  • Version Compare هنگام Reload
  • Rule Engine ساده (شرط ← عمل)
  • DataCenter Detection مبتنی بر کلیدواژه
  • Auto Cleanup خودکار (قابل تنظیم)
  • GitHub Source Finder (هر ۵ ساعت)
  • Benchmark فشرده
  • دو زبان فارسی/انگلیسی — اکنون به‌طور واقعی و کامل پیاده‌سازی شده
  • Memory Optimizer خودکار
  • Anomaly Detection (هشدار انحراف ناگهانی)
"""

# ── Standard library ──────────────────────────────────────────────────────────
import io, os, re, json, base64, random, hashlib, logging
import asyncio, time, math, sys, platform, socket, ipaddress, threading
from collections import defaultdict, OrderedDict
from datetime import datetime, timezone, timedelta
from functools import wraps
from urllib.parse import urlparse, unquote, quote
from zoneinfo import ZoneInfo

# ── Third-party ───────────────────────────────────────────────────────────────
import aiohttp
import aiosqlite
from tenacity import retry, stop_after_attempt, wait_exponential

# ── Telegram ──────────────────────────────────────────────────────────────────
from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Update, ForceReply
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    Application, ApplicationHandlerStop, CallbackQueryHandler,
    CommandHandler, ContextTypes, MessageHandler, filters,
)

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)
# httpx/httpcore هر request موفق getUpdates را با سطح INFO لاگ می‌کنند که برخی
# پلتفرم‌های میزبانی (از جمله بعضی حالت‌های Railway) آن را اشتباهاً "error" نشان
# می‌دهند. سطح این لاگرها را بالاتر می‌بریم تا فقط لاگ‌های واقعی ما دیده شوند.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)

# ═══════════════════════════════════════════════════════════════════════════════
# ENV HELPERS — خواندن امن متغیرهای محیطی (رفع کرش روی مقدار نامعتبر)
# ═══════════════════════════════════════════════════════════════════════════════
# قبلاً int(os.environ.get(...)) / float(os.environ.get(...)) مستقیم صدا زده
# می‌شد. اگر یک متغیر در Railway با مقدار خالی، فاصله، یا رشته‌ی غیرعددی ست
# می‌شد (مثلاً MAX_DAILY_REQUESTS="" یا "5 ")، کل پروسه همان لحظه‌ی import شدن
# ماژول با ValueError کرش می‌کرد — قبل از اینکه Config.validate() حتی فرصت
# گزارش‌دهی داشته باشد. این توابع چنین مقادیری را با لاگ هشدار به مقدار
# پیش‌فرض برمی‌گردانند تا بات فقط به‌خاطر یک متغیر محیطی خراب از کار نیفتد.
_ENV_WARNINGS: list = []

def _env_str(name: str, default: str) -> str:
    v = os.environ.get(name)
    return v if v is not None else default

def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except (ValueError, TypeError):
        _ENV_WARNINGS.append(f"{name}='{raw}' عدد صحیح معتبر نیست — مقدار پیش‌فرض ({default}) استفاده شد.")
        return default

def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw.strip())
    except (ValueError, TypeError):
        _ENV_WARNINGS.append(f"{name}='{raw}' عدد اعشاری معتبر نیست — مقدار پیش‌فرض ({default}) استفاده شد.")
        return default

def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    v = raw.strip().lower()
    if v in ("true", "1", "yes", "on"):   return True
    if v in ("false", "0", "no", "off"):  return False
    _ENV_WARNINGS.append(f"{name}='{raw}' مقدار بولی معتبر نیست (true/false) — مقدار پیش‌فرض ({default}) استفاده شد.")
    return default


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG  —  تمام متغیرها قابل تنظیم از Railway Environment Variables
# ═══════════════════════════════════════════════════════════════════════════════
class Config:
    # ── اجباری ─────────────────────────────────────────────────────────────────
    BOT_TOKEN:  str  = _env_str("BOT_TOKEN", "").strip()
    ADMIN_ID:   int  = _env_int("ADMIN_ID", 0)

    # ── کانال‌ها ────────────────────────────────────────────────────────────────
    CHANNEL_ID:       str = _env_str("CHANNEL_ID", "").strip()
    REQUIRED_CHANNEL: str = _env_str("REQUIRED_CHANNEL", "").strip()   # اگر خالی → بدون Force-Join

    # ── محدودیت کاربر ──────────────────────────────────────────────────────────
    MAX_DAILY_REQUESTS:      int = _env_int("MAX_DAILY_REQUESTS",      5)
    MAX_DAILY_CONFIGS:       int = _env_int("MAX_DAILY_CONFIGS",       50)
    MAX_CONFIGS_PER_REQUEST: int = _env_int("MAX_CONFIGS_PER_REQUEST", 500)
    VIP_MAX_DAILY_REQUESTS:  int = _env_int("VIP_MAX_DAILY_REQUESTS",  20)
    VIP_MAX_DAILY_CONFIGS:   int = _env_int("VIP_MAX_DAILY_CONFIGS",   200)

    # ── پست کانال ──────────────────────────────────────────────────────────────
    CHANNEL_POST_COUNT:          int = _env_int("CHANNEL_POST_COUNT",          10)
    CHANNEL_POST_INTERVAL:       int = _env_int("CHANNEL_POST_INTERVAL",       300)
    CHANNEL_FILTER_PROTOCOL:     str = _env_str("CHANNEL_FILTER_PROTOCOL",     "VLESS").strip().upper()
    CHANNEL_FILTER_COUNTRIES:   list = [
        c.strip().lower()
        for c in _env_str("CHANNEL_FILTER_COUNTRIES", "de,nl,fi,se,fr,gb,us,ca").split(",")
        if c.strip()
    ]

    # ── تایمینگ ─────────────────────────────────────────────────────────────────
    CACHE_REFRESH_INTERVAL: int = _env_int("CACHE_REFRESH_INTERVAL", 1200)
    AUTO_CLEANUP_INTERVAL:  int = _env_int("AUTO_CLEANUP_INTERVAL",  86400)
    GITHUB_SEARCH_INTERVAL: int = _env_int("GITHUB_SEARCH_INTERVAL", 18000)
    SEARCH_COOLDOWN:        int = _env_int("SEARCH_COOLDOWN",         30)

    # ── HTTP ─────────────────────────────────────────────────────────────────────
    FETCH_TIMEOUT:          int  = _env_int("FETCH_TIMEOUT",          15)
    MAX_CONCURRENT_FETCHES: int  = _env_int("MAX_CONCURRENT_FETCHES", 10)
    DISABLE_SSL_VERIFY:     bool = _env_bool("DISABLE_SSL_VERIFY", False)
    GITHUB_TOKEN:           str  = _env_str("GITHUB_TOKEN", "").strip()   # اختیاری، rate-limit بیشتر

    # ── کیفیت و فیلتر ───────────────────────────────────────────────────────────
    # FILTER_QUALITY حذف شد: طبق درخواست صریح ادمین، هیچ فیلتر کیفیت سلیقه‌ای
    # دیگر در بات وجود ندارد. تنها اعتبارسنجی باقی‌مانده ساختاری است
    # (ConfigStructureValidator) به‌علاوه‌ی IPBlacklist مدیریتی.
    MAX_CACHE_SIZE:  int  = _env_int("MAX_CACHE_SIZE", 50000)
    # طبق درخواست صریح ادمین، مقدار پیش‌فرض هاردکد حذف شد — این متغیر اکنون
    # کاملاً از طریق env var کنترل می‌شود. اگر ست نشود، هیچ برندی به کانفیگ‌ها
    # اضافه نمی‌شود (خالی = بدون برند).
    CONFIG_BRAND:    str  = _env_str("CONFIG_BRAND", "").strip()

    # ── هشدارهای هوشمند ─────────────────────────────────────────────────────────
    MIN_CACHE_NOTIFY:    int   = _env_int("MIN_CACHE_NOTIFY",    1000)
    CPU_ALERT_THRESHOLD: float = _env_float("CPU_ALERT_THRESHOLD", 85.0)
    MEM_ALERT_THRESHOLD: float = _env_float("MEM_ALERT_THRESHOLD", 80.0)
    MEM_OPTIMIZER_MB:    int   = _env_int("MEM_OPTIMIZER_MB",    350)

    # ── Abuse Detection ─────────────────────────────────────────────────────────
    ABUSE_WARN_THRESHOLD: int = _env_int("ABUSE_WARN_THRESHOLD", 10)
    ABUSE_MUTE_THRESHOLD: int = _env_int("ABUSE_MUTE_THRESHOLD", 25)
    ABUSE_BAN_THRESHOLD:  int = _env_int("ABUSE_BAN_THRESHOLD",  50)
    ABUSE_MUTE_MINUTES:   int = _env_int("ABUSE_MUTE_MINUTES",   60)

    # ── دیتابیس ──────────────────────────────────────────────────────────────────
    DB_PATH: str = _env_str("DB_PATH", "bot_database.db").strip()

    # ── زبان پیش‌فرض (fa / en) ───────────────────────────────────────────────────
    DEFAULT_LANGUAGE: str = _env_str("DEFAULT_LANGUAGE", "fa").strip().lower()

    # ── Real Ping Tester (Xray-core) ─────────────────────────────────────────────
    # هشدار منابع: روی پلن Railway با 0.5GB RAM، همزمانی بالا ریسک OOM دارد.
    # رفع باگ «تست‌شده همیشه فقط کسر کوچکی از کل کش است»: با مقادیر قبلی
    # سیستم Real Ping Tester (تست پینگ واقعی از طریق Xray) طبق درخواست صریح
    # ادمین به‌طور کامل حذف شد — همراه با آن، تمام متغیرهای PING_* و XRAY_*
    # نیز از بین رفته‌اند چون هیچ کاربردی ندارند. آدرس عمومی پنل تحت وب
    # (dashboard.py) روی Railway — برای ساخت لینک «پنل ادمین تحت وب» مستقیماً
    # از داخل خودِ بات. باید دقیقاً همان دامنه‌ای باشد که از Generate Domain
    # در Railway گرفته‌اید، بدون اسلش انتهایی (مثال: https://your-app.up.railway.app).
    WEBDASH_PUBLIC_URL:      str   = _env_str("WEBDASH_PUBLIC_URL", "").strip().rstrip("/")
    ADMIN_PANEL_TOKEN:       str   = _env_str("ADMIN_PANEL_TOKEN", "").strip()

    # ── ConfigReputation — سقف حافظه (رفع رشد بی‌نهایت دیکشنری کش) ──────────────
    REPUTATION_MAX_ENTRIES:  int   = _env_int("REPUTATION_MAX_ENTRIES", 20000)

    # ── SSRFGuard — رفع باگ #17 (عدم وجود Timeout در resolve دامنه) ─────────────
    DNS_RESOLVE_TIMEOUT: float = _env_float("DNS_RESOLVE_TIMEOUT", 5.0)

    # ── GitHubSourceFinder — رفع باگ #18 (رشد بی‌نهایت جدول github_sources) ─────
    GITHUB_SOURCES_MAX_AGE_DAYS: int = _env_int("GITHUB_SOURCES_MAX_AGE_DAYS", 60)

    @classmethod
    def validate(cls) -> None:
        missing = [k for k, v in [("BOT_TOKEN", cls.BOT_TOKEN), ("ADMIN_ID", str(cls.ADMIN_ID))]
                   if not v or v == "0"]
        if missing:
            raise ValueError(f"❌ متغیرهای اجباری: {', '.join(missing)}")
        logger.info("✅ تنظیمات تأیید شد.")
        if cls.DISABLE_SSL_VERIFY:
            logger.warning(
                "⚠️  DISABLE_SSL_VERIFY=true — تأیید گواهی SSL برای دریافت منابع "
                "غیرفعال است؛ بات در برابر حملات Man-in-the-Middle روی این اتصالات "
                "آسیب‌پذیر می‌شود. فقط در صورت نیاز واقعی (مثلاً منبع داخلی با "
                "گواهی self-signed) فعال نگه دارید.")
        # هر متغیر محیطی که مقدار نامعتبر داشته (و به پیش‌فرض بازگردانده شده) را
        # اینجا با صدای بلند (WARNING، نه فقط silent fallback) گزارش می‌دهیم تا
        # ادمین در لاگ‌های Railway متوجه‌ی خرابی مقدار شود.
        for w in _ENV_WARNINGS:
            logger.warning(f"⚠️  متغیر محیطی نامعتبر: {w}")
        if not _ENV_WARNINGS:
            logger.info("✅ همه‌ی متغیرهای محیطی عددی/بولی معتبر بودند.")


# ═══════════════════════════════════════════════════════════════════════════════
# منابع پیش‌فرض
# ═══════════════════════════════════════════════════════════════════════════════
DEFAULT_SOURCES: list = [
    "https://sub.whitedns.shop/sub/base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/FRAGMENT",
    "https://raw.githubusercontent.com/ShadowException/VPN/refs/heads/main/configs/VPN-cat",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub3.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/subscriptions/all.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://mifa.world/ss", "https://mifa.world/trojan", "https://mifa.world/hysteria",
    "https://mifa.world/other", "https://mifa.world/vmess", "https://mifa.world/vless",
    "https://raw.githubusercontent.com/pytimusprime/FreeV2ray/refs/heads/main/all_servers.txt",
    "https://raw.githubusercontent.com/ThomasJasperthecat/sub/main/sublist1.txt",
    "https://raw.githubusercontent.com/masir-sefid/Sub/main/@Masir_Sefid.txt",
    "https://raw.githubusercontent.com/AmyraxVPN-Main/AmyraxVPN/refs/heads/main/AmyraxVPN.txt",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/refs/heads/main/Configs/VLESS-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "https://raw.githubusercontent.com/YawStar/Proxy-Hunter/refs/heads/main/configs/proxy_configs_tested.txt",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/countries/us/mixed",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/countries/jp/mixed",
    # ── درخواست‌شده توسط ادمین (اضافه شد) ──────────────────────────────────
    "https://raw.githubusercontent.com/flaafix/AetrisVPN/refs/heads/main/AetrisVPN.txt",
    "https://raw.githubusercontent.com/sinavm/SVM/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/vless.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
]

# منابعی که ادمین صریحاً درخواست حذف داده — چه در DEFAULT_SOURCES بالا نباشند
# (نسخه‌های تازه) چه در جدول sources یک نصب قدیمی‌تر از قبل موجود باشند، این
# لیست هم برای فیلتر seed اولیه و هم برای حذف واقعی رکوردهای موجود در دیتابیس
# (در init_db، هر بار در استارتاپ) استفاده می‌شود تا نصب‌های در حال اجرا هم
# این منابع را واقعاً از دست بدهند، نه فقط نصب‌های تازه.
REMOVED_SOURCES: list = [
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/normal/trojan",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
]

def webdash_configured() -> bool:
    """آیا پنل تحت وب ادمین دیپلوی و در دسترس است (WEBDASH_PUBLIC_URL ست شده)."""
    return bool(Config.WEBDASH_PUBLIC_URL)

def admin_panel_url() -> str:
    return f"{Config.WEBDASH_PUBLIC_URL}/admin?token={Config.ADMIN_PANEL_TOKEN}"

# ═══════════════════════════════════════════════════════════════════════════════
# نقشه کشورها
# ═══════════════════════════════════════════════════════════════════════════════
# رفع درخواست ادمین «فیلتر کشور بسیار قوی‌تر» + «زبان انگلیسی بسیار بهتر»:
# این نقشه از ۲۹ کشور به یک فهرست بسیار جامع‌تر (کشورهای رایج هاستینگ/VPN در
# سراسر دنیا، نه فقط اروپا/آمریکای شمالی) گسترش یافت، و مهم‌تر: هر کشور حالا
# نام انگلیسی مستقل هم دارد (قبلاً country_display پارامتر lang را می‌گرفت
# ولی هرگز واقعاً استفاده نمی‌کرد — همیشه فقط فارسی نمایش داده می‌شد،
# صرف‌نظر از زبان انتخابی کاربر).
COUNTRY_MAP: dict = {
    "de": ("🇩🇪","آلمان","Germany"),           "nl": ("🇳🇱","هلند","Netherlands"),
    "fi": ("🇫🇮","فنلاند","Finland"),          "se": ("🇸🇪","سوئد","Sweden"),
    "fr": ("🇫🇷","فرانسه","France"),           "gb": ("🇬🇧","انگلستان","United Kingdom"),
    "us": ("🇺🇸","آمریکا","United States"),    "ca": ("🇨🇦","کانادا","Canada"),
    "jp": ("🇯🇵","ژاپن","Japan"),              "sg": ("🇸🇬","سنگاپور","Singapore"),
    "ru": ("🇷🇺","روسیه","Russia"),            "ua": ("🇺🇦","اوکراین","Ukraine"),
    "br": ("🇧🇷","برزیل","Brazil"),            "au": ("🇦🇺","استرالیا","Australia"),
    "in": ("🇮🇳","هند","India"),               "kr": ("🇰🇷","کره جنوبی","South Korea"),
    "tr": ("🇹🇷","ترکیه","Turkey"),            "at": ("🇦🇹","اتریش","Austria"),
    "ch": ("🇨🇭","سوئیس","Switzerland"),       "pl": ("🇵🇱","لهستان","Poland"),
    "cz": ("🇨🇿","چک","Czechia"),              "ro": ("🇷🇴","رومانی","Romania"),
    "hu": ("🇭🇺","مجارستان","Hungary"),        "lt": ("🇱🇹","لیتوانی","Lithuania"),
    "lv": ("🇱🇻","لتونی","Latvia"),            "ee": ("🇪🇪","استونی","Estonia"),
    "no": ("🇳🇴","نروژ","Norway"),             "dk": ("🇩🇰","دانمارک","Denmark"),
    "es": ("🇪🇸","اسپانیا","Spain"),           "it": ("🇮🇹","ایتالیا","Italy"),
    # ── گسترش جدید: خاورمیانه، آسیا، اقیانوسیه، آمریکای لاتین، آفریقا ──────
    "ae": ("🇦🇪","امارات","United Arab Emirates"), "sa": ("🇸🇦","عربستان","Saudi Arabia"),
    "il": ("🇮🇱","اسرائیل","Israel"),          "eg": ("🇪🇬","مصر","Egypt"),
    "hk": ("🇭🇰","هنگ‌کنگ","Hong Kong"),        "tw": ("🇹🇼","تایوان","Taiwan"),
    "my": ("🇲🇾","مالزی","Malaysia"),          "th": ("🇹🇭","تایلند","Thailand"),
    "vn": ("🇻🇳","ویتنام","Vietnam"),          "id": ("🇮🇩","اندونزی","Indonesia"),
    "ph": ("🇵🇭","فیلیپین","Philippines"),     "cn": ("🇨🇳","چین","China"),
    "za": ("🇿🇦","آفریقای جنوبی","South Africa"), "mx": ("🇲🇽","مکزیک","Mexico"),
    "ar": ("🇦🇷","آرژانتین","Argentina"),      "cl": ("🇨🇱","شیلی","Chile"),
    "co": ("🇨🇴","کلمبیا","Colombia"),         "ie": ("🇮🇪","ایرلند","Ireland"),
    "pt": ("🇵🇹","پرتغال","Portugal"),         "be": ("🇧🇪","بلژیک","Belgium"),
    "gr": ("🇬🇷","یونان","Greece"),            "bg": ("🇧🇬","بلغارستان","Bulgaria"),
    "hr": ("🇭🇷","کرواسی","Croatia"),          "sk": ("🇸🇰","اسلواکی","Slovakia"),
    "si": ("🇸🇮","اسلوونی","Slovenia"),        "is": ("🇮🇸","ایسلند","Iceland"),
    "lu": ("🇱🇺","لوکزامبورگ","Luxembourg"),   "md": ("🇲🇩","مولداوی","Moldova"),
    "rs": ("🇷🇸","صربستان","Serbia"),          "kz": ("🇰🇿","قزاقستان","Kazakhstan"),
    "ge": ("🇬🇪","گرجستان","Georgia"),         "am": ("🇦🇲","ارمنستان","Armenia"),
    "az": ("🇦🇿","آذربایجان","Azerbaijan"),
}
_UNKNOWN_COUNTRY = ("🏳️","نامشخص","Unspecified")

def country_display(code: str, lang: str = "fa") -> str:
    """
    رفع باگ «همیشه فارسی نشان می‌دهد»: قبلاً پارامتر lang گرفته می‌شد ولی
    هرگز واقعاً بررسی نمی‌شد — این تابع همیشه name_fa را برمی‌گرداند، حتی
    برای کاربرانی که زبان انگلیسی را انتخاب کرده بودند. حالا واقعاً بر اساس
    lang انتخاب می‌کند.
    """
    if code == "ALL":
        return "🌍 همه لوکیشن‌ها" if lang == "fa" else "🌍 All Locations"
    flag, name_fa, name_en = COUNTRY_MAP.get(code, _UNKNOWN_COUNTRY)
    return f"{flag} {name_fa}" if lang == "fa" else f"{flag} {name_en}"

# ═══════════════════════════════════════════════════════════════════════════════
# I18N — دو زبان فارسی و انگلیسی
# ═══════════════════════════════════════════════════════════════════════════════
_T: dict = {
    "fa": {
        "welcome":           "🛡 *مرکز کانفیگ V2Ray — دسترسی پریمیوم*",
        "loading":           "🔄 در حال بارگذاری کش...",
        "get_configs":       "📦 دریافت کانفیگ",
        "random_cfg":        "🎲 کانفیگ تصادفی",
        "filter_proto":      "🔧 فیلتر پروتکل",
        "filter_country":    "🌍 فیلتر کشور",
        "search_cfg":        "🔍 جستجوی کانفیگ",
        "my_profile":        "👤 پروفایل من",
        "admin_panel":       "👑 پنل ادمین",
        "back":              "🔙 بازگشت",
        "cancel":            "❌ انصراف",
        "join_channel":      "📢 عضویت در کانال",
        "force_join_msg":    "🔒 برای دسترسی باید در کانال ما عضو باشید 👇",
        "daily_limit":       "⚠️ سقف روزانه تمام شده. فردا مجدداً تلاش کنید.",
        "no_configs":        "❌ کانفیگی با این فیلترها یافت نشد.",
        "enter_count":       "🔢 چند کانفیگ می‌خواهید؟",
        "enter_search":      "🔍 عبارت جستجو را وارد کنید:\n\nمثال: `germany vless` یا `us reality`",
        "search_cooldown":   "⏳ تا {sec} ثانیه دیگر صبر کنید.",
        "search_results":    "🔍 {count} کانفیگ یافت شد. چند تا می‌خواهید؟",
        "search_none":       "❌ کانفیگی با این عبارت یافت نشد.",
        "feedback_prompt":   "❗ گزارش مشکل",
        "feedback_sent":     "✅ گزارش شما ثبت شد. ممنون!",
        "feedback_not_work": "❌ کار نمی‌کند",
        "feedback_slow":     "🐌 پینگ بالا",
        "feedback_weak":     "📶 اتصال ضعیف",
        "vip_badge":         "⭐ VIP",
        "lang_toggle":       "🌐 English",
        "proto_select":      "🔧 پروتکل مورد نظر:",
        "country_select":    "🌍 کشور مقصد:",
        "sent_file":         "📦 {n} کانفیگ",
        "abuse_warned":      "⚠️ هشدار: رفتار غیرعادی شناسایی شد.",
        "muted":             "🔇 دسترسی شما موقتاً محدود شده است.",
        "invalid_number":    "❌ عدد صحیح مثبت وارد کنید.",
        "search_empty":      "❌ عبارت جستجو نمی‌تواند خالی باشد.",
        "tested_disabled":   "این قابلیت موقتاً غیرفعال است.",
    },
    "en": {
        "welcome":           "🛡 *V2Ray Config Hub — Premium Access*",
        "loading":           "🔄 Loading cache...",
        "get_configs":       "📦 Get Configs",
        "random_cfg":        "🎲 Random Config",
        "filter_proto":      "🔧 Filter Protocol",
        "filter_country":    "🌍 Filter Country",
        "search_cfg":        "🔍 Search Config",
        "my_profile":        "👤 My Profile",
        "admin_panel":       "👑 Admin Panel",
        "back":              "🔙 Back",
        "cancel":            "❌ Cancel",
        "join_channel":      "📢 Join Channel",
        "force_join_msg":    "🔒 Please join our channel to get access 👇",
        "daily_limit":       "⚠️ Daily limit reached. Try again tomorrow.",
        "no_configs":        "❌ No configs found with these filters.",
        "enter_count":       "🔢 How many configs do you want?",
        "enter_search":      "🔍 Enter your search query:\n\nExample: `germany vless` or `us reality`",
        "search_cooldown":   "⏳ Wait {sec} more seconds.",
        "search_results":    "🔍 Found {count} configs. How many do you want?",
        "search_none":       "❌ No configs found for this query.",
        "feedback_prompt":   "❗ Report Issue",
        "feedback_sent":     "✅ Feedback recorded. Thank you!",
        "feedback_not_work": "❌ Not Working",
        "feedback_slow":     "🐌 High Ping",
        "feedback_weak":     "📶 Weak Connection",
        "vip_badge":         "⭐ VIP",
        "lang_toggle":       "🌐 فارسی",
        "proto_select":      "🔧 Select protocol:",
        "country_select":    "🌍 Select country:",
        "sent_file":         "📦 {n} Configs",
        "abuse_warned":      "⚠️ Warning: abnormal behavior detected.",
        "muted":             "🔇 Your access has been temporarily restricted.",
        "invalid_number":    "❌ Please enter a positive whole number.",
        "search_empty":      "❌ Search query cannot be empty.",
        "tested_disabled":   "This feature is currently disabled.",
    },
}

def T(key: str, lang: str = "fa", **kw) -> str:
    s = _T.get(lang, _T["fa"]).get(key, _T["fa"].get(key, key))
    return s.format(**kw) if kw else s

# ═══════════════════════════════════════════════════════════════════════════════
# DataCenter Detection — شناسایی ارائه‌دهنده هاستینگ از روی hostname
# ═══════════════════════════════════════════════════════════════════════════════
_DC_MAP = {
    "hetzner": "Hetzner", "hetzner.cloud": "Hetzner",
    "ovh": "OVH", "ovhcloud": "OVH",
    "contabo": "Contabo",
    "digitalocean": "DigitalOcean", "droplet": "DigitalOcean",
    "vultr": "Vultr",
    "amazonaws": "AWS", "aws": "AWS",
    "azure": "Azure",
    "cloud.google": "GCP", "gce": "GCP", "gcp": "GCP",
    "alibaba": "Alibaba", "aliyun": "Alibaba",
    "oracle": "Oracle Cloud",
    "linode": "Akamai/Linode", "akamai": "Akamai/Linode",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly",
    "upcloud": "UpCloud",
    "ionos": "IONOS",
    "scaleway": "Scaleway",
}

def detect_datacenter(host: str) -> str:
    h = host.lower()
    for kw, dc in _DC_MAP.items():
        if kw in h:
            return dc
    return "Unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# BrandingEngine — پاک‌سازی رمارک و اعمال برند
# ═══════════════════════════════════════════════════════════════════════════════
class BrandingEngine:
    """
    رفع باگ‌های #11 تا #15 (استخراج نشدن اسم کانفیگ / نمایش «none» در v2rayNG،
    و از دست رفتن اطلاعات مفید در اسم):

    قبلاً منطق برندسازی این‌طور بود: اگر CONFIG_BRAND خالی بود، هیچ اسمی به
    کانفیگ اضافه نمی‌شد (و برای URIهایی که خودشان # نداشتند، هیچ ریمارکی
    وجود نداشت — کلاینت‌هایی مثل v2rayNG معمولاً «none»/خالی نمایش می‌دادند).
    و اگر CONFIG_BRAND ست شده بود، فیلد ps/ریمارک اصلی کانفیگ به‌طور کامل با
    برند جایگزین می‌شد و نام اصلی (و هر اطلاعات مفیدی مثل کشور/پروتکل)
    گم می‌شد.

    منطق جدید (هم برای برند خالی و هم پر):
      ۱. نام اصلی کانفیگ (ps در vmess، یا بخش #remark در سایر پروتکل‌ها) اگر
         وجود داشته باشد، همیشه نگه داشته می‌شود — نه بازنویسی و نه حذف.
      ۲. یک نام پیش‌فرض مفید بر اساس پرچم/کشور و پروتکل تولید می‌شود (مثلاً
         «🇩🇪 Germany VLESS») تا هیچ کانفیگی هرگز بدون اسم یا با «none»
         به کلاینت نرسد.
      ۳. اگر CONFIG_BRAND ست شده باشد، به‌عنوان پیشوند به نام نهایی اضافه
         می‌شود (نه جایگزین آن) — مثلاً «[MyBrand] 🇩🇪 Germany VLESS» یا اگر
         نام اصلی کانفیگ وجود داشت: «[MyBrand] OriginalName».
    """

    @classmethod
    def _default_name(cls, country: str, protocol: str) -> str:
        flag, name_fa, name_en = COUNTRY_MAP.get(country, _UNKNOWN_COUNTRY)
        proto_label = (protocol or "").upper() or "VPN"
        return f"{flag} {name_en} {proto_label}".strip()

    @classmethod
    def apply(cls, cfg: str, country: str = "", protocol: str = "") -> str:
        brand = Config.CONFIG_BRAND
        cfg   = cfg.strip()
        try:
            if cfg.lower().startswith("vmess://"):
                return cls._brand_vmess(cfg, brand, country, protocol)
            return cls._brand_uri(cfg, brand, country, protocol)
        except Exception:
            return cls._brand_uri(cfg, brand, country, protocol)

    @classmethod
    def _brand_vmess(cls, cfg: str, brand: str, country: str, protocol: str) -> str:
        b64 = cfg[8:].strip() + "=" * ((4 - len(cfg[8:].strip()) % 4) % 4)
        try:
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
        except Exception as exc:
            logger.warning(f"BrandingEngine: پارس JSON کانفیگ vmess ناموفق — برند به fragment منتقل شد (نه فیلد ps): {exc}")
            return cls._brand_uri(cfg, brand, country, protocol)
        original_ps = str(data.get("ps") or "").strip()
        base_name   = original_ps if original_ps else cls._default_name(country, protocol)
        data["ps"]  = f"[{brand}] {base_name}" if brand else base_name
        new_b64 = base64.b64encode(
            json.dumps(data, ensure_ascii=False, separators=(",",":")).encode()
        ).decode()
        return f"vmess://{new_b64}"

    @classmethod
    def _brand_uri(cls, cfg: str, brand: str, country: str, protocol: str) -> str:
        original_remark = ""
        if "#" in cfg:
            cfg, _, frag = cfg.partition("#")
            try:
                original_remark = unquote(frag).strip()
            except Exception:
                original_remark = frag.strip()
        base_name = original_remark if original_remark else cls._default_name(country, protocol)
        final_name = f"[{brand}] {base_name}" if brand else base_name
        return f"{cfg}#{quote(final_name)}"

# ═══════════════════════════════════════════════════════════════════════════════
# CountryDetector — تشخیص کشور صرفاً regex-based
# ═══════════════════════════════════════════════════════════════════════════════
class CountryDetector:
    """
    رفع درخواست «فیلتر کشور بسیار حرفه‌ای‌تر شود» + رفع باگ ضمنی «کانفیگ‌های
    منابع با ریمارک استیکری/ایموجی انگار حذف می‌شوند»: نسخه‌ی قبلی فقط به
    نام فارسی کشور در COUNTRY_MAP و یک regex ساده‌ی دو-حرفی وابسته بود. یک
    ریمارک مثل «🇩🇪 Germany #1 🔥» یا «DE-Premium-01» یا شهرهایی مثل
    Frankfurt/Amsterdam اصلاً تشخیص داده نمی‌شد و کانفیگ به‌عنوان «ALL»
    (نامشخص) ثبت می‌شد — این یعنی از دید فیلتر کشور کاربر، انگار کانفیگ
    اصلاً وجود نداشت (نه اینکه واقعاً حذف شده باشد، ولی حسِ «حذف‌شدن» را
    القا می‌کند). نسخه‌ی جدید این منابع را هم بررسی می‌کند:
      • ایموجی پرچم کشور (خیلی از منابع دقیقاً همین را در ریمارک می‌گذارند)
      • نام انگلیسی کامل کشور (نه فقط فارسی)
      • کد ISO-3166 آلفا-۲ با مرزبندی صحیح کلمه (نه یک substring خام)
      • نام شهرهای پرکاربرد هاستینگ/VPN (فرانکفورت، آمستردام، سنگاپور، ...)
    ترتیب اولویت: پرچم ایموجی > نام کامل کشور (fa/en) > نام شهر > کد دو-حرفی.
    """
    _HOST_RE   = re.compile(r"@([^:/@\s?#\[\]]+)", re.IGNORECASE)
    _CODE_SEP  = re.compile(r"(?:^|[-_./ |,])([a-zA-Z]{2})(?:[-_./ |,]|$)")

    # پرچم‌های ایموجی → کد کشور (تولید خودکار از COUNTRY_MAP + چند مورد رایج
    # اضافه که ممکن است در COUNTRY_MAP نباشند اما در ریمارک منابع دیده شوند).
    _FLAG_TO_CODE: dict = {}

    # اسم‌های رایج شهرهای هاستینگ/دیتاسنتر که در ریمارک‌ها به‌جای اسم کشور
    # استفاده می‌شوند. طبق درخواست ادمین (فیلتر کشور بسیار قوی‌تر)، شهرهای
    # کشورهای تازه‌اضافه‌شده (خاورمیانه، آسیا، آمریکای لاتین) هم اضافه شدند.
    _CITY_TO_CODE: dict = {
        "frankfurt":"de", "berlin":"de", "munich":"de", "nuremberg":"de", "falkenstein":"de",
        "amsterdam":"nl",
        "helsinki":"fi",
        "stockholm":"se",
        "paris":"fr", "marseille":"fr", "strasbourg":"fr", "gravelines":"fr", "roubaix":"fr",
        "london":"gb", "manchester":"gb",
        "newyork":"us", "new york":"us", "losangeles":"us", "los angeles":"us",
        "dallas":"us", "chicago":"us", "seattle":"us", "miami":"us", "ashburn":"us",
        "sanjose":"us", "san jose":"us", "sunnyvale":"us", "portland":"us", "vint hill":"us",
        "toronto":"ca", "montreal":"ca",
        "tokyo":"jp", "osaka":"jp",
        "singapore":"sg",
        "moscow":"ru", "petersburg":"ru", "moskva":"ru",
        "kyiv":"ua", "kiev":"ua",
        "saopaulo":"br", "sao paulo":"br",
        "sydney":"au", "melbourne":"au",
        "mumbai":"in", "bangalore":"in", "delhi":"in", "chennai":"in",
        "seoul":"kr",
        "istanbul":"tr", "ankara":"tr",
        "vienna":"at",
        "zurich":"ch", "geneva":"ch",
        "warsaw":"pl",
        "prague":"cz",
        "bucharest":"ro",
        "budapest":"hu",
        "vilnius":"lt",
        "riga":"lv",
        "tallinn":"ee",
        "oslo":"no",
        "copenhagen":"dk",
        "madrid":"es", "barcelona":"es",
        "milan":"it", "rome":"it",
        "dubai":"ae", "abudhabi":"ae", "abu dhabi":"ae",
        "riyadh":"sa", "jeddah":"sa",
        "telaviv":"il", "tel aviv":"il", "jerusalem":"il",
        "cairo":"eg",
        "hongkong":"hk", "hong kong":"hk",
        "taipei":"tw",
        "kualalumpur":"my", "kuala lumpur":"my",
        "bangkok":"th",
        "hanoi":"vn", "hochiminh":"vn", "ho chi minh":"vn", "saigon":"vn",
        "jakarta":"id",
        "manila":"ph",
        "shanghai":"cn", "beijing":"cn", "guangzhou":"cn", "shenzhen":"cn",
        "johannesburg":"za", "capetown":"za", "cape town":"za",
        "mexicocity":"mx", "mexico city":"mx",
        "buenosaires":"ar", "buenos aires":"ar",
        "santiago":"cl",
        "bogota":"co", "bogotá":"co",
        "dublin":"ie",
        "lisbon":"pt", "porto":"pt",
        "brussels":"be",
        "athens":"gr",
        "sofia":"bg",
        "zagreb":"hr",
        "bratislava":"sk",
        "ljubljana":"si",
        "reykjavik":"is",
        "chisinau":"md",
        "belgrade":"rs",
        "almaty":"kz", "astana":"kz",
        "tbilisi":"ge",
        "yerevan":"am",
        "baku":"az",
    }

    @classmethod
    def _build_flag_map(cls) -> dict:
        if cls._FLAG_TO_CODE:
            return cls._FLAG_TO_CODE
        for code, (flag, _name_fa, _name_en) in COUNTRY_MAP.items():
            cls._FLAG_TO_CODE[flag] = code
        return cls._FLAG_TO_CODE

    @classmethod
    def detect(cls, cfg: str) -> str:
        cfg_lower = cfg.lower()
        hostname = remark = ""
        if cfg_lower.startswith("vmess://"):
            try:
                b64  = cfg[8:].strip()
                b64 += "=" * ((4 - len(b64) % 4) % 4)
                data     = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
                hostname = str(data.get("add","")).lower()
                remark   = str(data.get("ps",""))   # پرچم ایموجی حساس به کوچک/بزرگی نیست ولی case اصلی متن حفظ شود
            except Exception:
                pass
        else:
            m = cls._HOST_RE.search(cfg)
            if m: hostname = m.group(1).lower()
            if "#" in cfg: remark = unquote(cfg[cfg.index("#")+1:])

        remark_lower = remark.lower()
        blob = f"{cfg_lower} {hostname} {remark_lower}"

        # ۱) پرچم ایموجی — قوی‌ترین سیگنال، چون تقریباً هرگز اشتباه نیست.
        flag_map = cls._build_flag_map()
        for flag, code in flag_map.items():
            if flag in remark:
                return code

        # ۲) نام کامل کشور — هم فارسی هم انگلیسی، مستقیماً از COUNTRY_MAP
        # (که حالا خودش نام انگلیسی هر کشور را دارد؛ دیگر نیازی به یک
        # دیکشنری انگلیسی جداگانه‌ی کوچک‌تر نیست).
        for code, (_flag, name_fa, name_en) in COUNTRY_MAP.items():
            if name_fa in blob or name_en.lower() in blob:
                return code

        # ۳) نام شهرهای پرکاربرد هاستینگ/VPN.
        blob_compact = re.sub(r"[-_.]", "", blob)
        for city, code in cls._CITY_TO_CODE.items():
            city_compact = city.replace(" ", "")
            if city in blob or city_compact in blob_compact:
                return code

        # ۴) کد دو-حرفی با مرزبندی صحیح کلمه (نه substring خام — رفع باگ
        # false-positive قدیمی مثل «us» داخل کلمه‌ی «house» یا «trust»).
        for src in (remark_lower, hostname):
            if not src: continue
            for m in cls._CODE_SEP.finditer(src):
                c = m.group(1).lower()
                if c in COUNTRY_MAP: return c
            for part in re.split(r"[-_./|, ]", src):
                if len(part) == 2 and part in COUNTRY_MAP: return part

        return "ALL"


# ═══════════════════════════════════════════════════════════════════════════════
# AdvancedDeduplicator — dedup بر اساس fingerprint (نه فقط رشته مساوی)
# ═══════════════════════════════════════════════════════════════════════════════
class AdvancedDeduplicator:
    """
    fingerprint = sha256(normalized_key)
    کلید نرمال‌سازی‌شده:
      vmess  → add:port:id
      others → host:port:uuid_or_first64chars_of_path
    """
    _HOST_PORT_RE = re.compile(r"@([^:/@\s?#\[\]]+):(\d{1,5})")
    _UUID_RE      = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
    )

    @classmethod
    def fingerprint(cls, cfg: str) -> str:
        cfg = cfg.strip()
        lower = cfg.lower()
        try:
            if lower.startswith("vmess://"):
                b64  = cfg[8:].strip()
                b64 += "=" * ((4 - len(b64) % 4) % 4)
                d    = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
                key  = f"{d.get('add','')}:{d.get('port','')}:{d.get('id','')}"
                return hashlib.sha256(key.lower().encode()).hexdigest()[:16]

            m_hp = cls._HOST_PORT_RE.search(cfg)
            host = m_hp.group(1).lower() if m_hp else ""
            port = m_hp.group(2)         if m_hp else "0"
            m_uuid = cls._UUID_RE.search(cfg)
            uid  = m_uuid.group(0).lower() if m_uuid else cfg[10:74]
            key  = f"{host}:{port}:{uid}"
            return hashlib.sha256(key.encode()).hexdigest()[:16]
        except Exception:
            return hashlib.sha256(cfg[:128].encode()).hexdigest()[:16]

# ═══════════════════════════════════════════════════════════════════════════════
# IPBlacklist — بلاک IP های مخرب
# ═══════════════════════════════════════════════════════════════════════════════
class IPBlacklist:
    _set: set = set()   # in-memory fast lookup

    @classmethod
    def load(cls, ips: list) -> None:
        cls._set = set(ips)

    @classmethod
    def add(cls, ip: str) -> None:
        cls._set.add(ip.strip())

    @classmethod
    def is_blocked(cls, ip_or_host: str) -> bool:
        return ip_or_host.strip() in cls._set

    @classmethod
    def extract_host(cls, cfg: str) -> str:
        m = re.search(r"@([^:/@\s?#\[\]]+)", cfg)
        return m.group(1) if m else ""

    @classmethod
    def config_is_blocked(cls, cfg: str) -> bool:
        host = cls.extract_host(cfg)
        return bool(host) and cls.is_blocked(host)

# ═══════════════════════════════════════════════════════════════════════════════
# SSRFGuard — جلوگیری از افزودن منبع داخلی/مخرب از طریق /addsource
# ═══════════════════════════════════════════════════════════════════════════════
# رفع باگ «امکان SSRF»: قبلاً /addsource فقط scheme و netloc را چک می‌کرد و
# هیچ اعتبارسنجی روی خودِ آدرس IP انجام نمی‌داد. یک ادمین (یا هر کسی که به
# این دستور دسترسی پیدا کند) می‌توانست یک URL داخلی مثل
# http://169.254.169.254/latest/meta-data (سرویس متادیتای AWS/GCP/Railway
# داخلی) یا http://localhost:PORT اضافه کند و بات (که خودش fetch را انجام
# می‌دهد) را وادار به درخواست به شبکه‌ی داخلی کانتینر کند. این کلاس هاست را
# resolve کرده و هر IP بازگشتی را در برابر بازه‌های خصوصی/loopback/link-local
# چک می‌کند — نه فقط ظاهر رشته‌ی URL را.
class SSRFGuard:
    @staticmethod
    def _is_dangerous_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True   # اگر حتی parse نشد، برای احتیاط مسدود می‌کنیم
        return (
            ip.is_private or ip.is_loopback or ip.is_link_local or
            ip.is_multicast or ip.is_reserved or ip.is_unspecified or
            ip.is_site_local
        )

    @classmethod
    async def is_safe_url(cls, url: str) -> "tuple[bool, str]":
        """
        برمی‌گرداند (safe, reason_if_unsafe).

        رفع باگ «بلاک‌شدن event loop روی /addsource»: قبلاً socket.getaddrinfo
        (که یک فراخوانی synchronous و کند شبکه است) مستقیم داخل یک تابع async
        صدا زده می‌شد. چون این تابع خودش await نمی‌کرد، در عمل کل event loop
        بات (یعنی رسیدگی به تمام کاربران دیگر هم‌زمان) تا تمام‌شدن resolve
        دامنه فریز می‌شد. حالا resolve با loop.run_in_executor در یک ترد
        جداگانه اجرا می‌شود تا event loop اصلی هرگز بلاک نشود.

        رفع باگ #17 (عدم وجود Timeout): run_in_executor به‌تنهایی فقط از
        بلاک‌شدن *event loop* جلوگیری می‌کند — اما اگر DNS قطع یا خیلی کند
        باشد، خودِ future این executor همچنان می‌تواند برای همیشه معلق بماند
        و دستور /addsource ادمین را (نه کل بات را) بی‌نهایت منتظر نگه دارد.
        حالا این resolve با asyncio.wait_for و سقف زمانی صریح
        Config.DNS_RESOLVE_TIMEOUT محدود شده؛ در صورت timeout، URL رد
        می‌شود و پیام خطای روشن به ادمین برمی‌گردد، نه یک هنگ بی‌پایان.
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "URL قابل‌پارس نیست."
        if parsed.scheme not in ("http", "https"):
            return False, "فقط http/https مجاز است."
        host = parsed.hostname
        if not host:
            return False, "میزبان (host) در URL یافت نشد."
        host_lower = host.lower()
        if host_lower in ("localhost", "metadata", "metadata.google.internal"):
            return False, f"میزبان '{host}' مسدود است (آدرس داخلی/متادیتا)."
        # اگر خودِ host یک IP لیترال باشد
        try:
            ipaddress.ip_address(host)
            if cls._is_dangerous_ip(host):
                return False, f"آدرس IP '{host}' در بازه‌ی خصوصی/داخلی/متادیتا است."
            return True, ""
        except ValueError:
            pass   # host یک دامنه است، نه IP خام — باید resolve شود
        # Resolve دامنه و چک همه‌ی IP های بازگشتی (defense-in-depth در برابر
        # DNS rebinding: اگر حتی یکی از IP ها خطرناک باشد، کل URL رد می‌شود).
        try:
            loop  = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.run_in_executor(None, socket.getaddrinfo, host, None),
                timeout=Config.DNS_RESOLVE_TIMEOUT)
        except asyncio.TimeoutError:
            return False, f"resolve نام دامنه بیش از {Config.DNS_RESOLVE_TIMEOUT:.0f} ثانیه طول کشید (timeout)."
        except Exception as exc:
            return False, f"resolve نام دامنه ناموفق بود: {exc}"
        resolved_ips = {info[4][0] for info in infos}
        if not resolved_ips:
            return False, "هیچ IP ای برای این دامنه resolve نشد."
        for ip_str in resolved_ips:
            if cls._is_dangerous_ip(ip_str):
                return False, f"دامنه به آدرس داخلی/خصوصی ({ip_str}) resolve می‌شود."
        return True, ""

# ═══════════════════════════════════════════════════════════════════════════════
# ConfigStructureValidator — اعتبارسنجی فرمت URI (این فیلتر کیفیت نیست — صرفاً
# چک می‌کند که رشته اصلاً یک URI معتبر با فیلدهای الزامی است، مثلاً کانفیگ
# vmess با base64 خراب یا بدون فیلد port. این تنها لایه‌ی رد کانفیگ باقی‌مانده
# در بات است؛ طبق درخواست ادمین، هیچ فیلتر «کیفیت» سلیقه‌ای دیگری اعمال
# نمی‌شود.)
# ═══════════════════════════════════════════════════════════════════════════════
class ConfigStructureValidator:
    @staticmethod
    def is_valid(cfg: str) -> bool:
        s, lower = cfg.strip(), cfg.strip().lower()
        try:
            if lower.startswith(("vless://","trojan://","tuic://")):
                return "@" in s and ":" in s
            if lower.startswith("vmess://"):
                b64  = s[8:].strip()
                b64 += "=" * ((4 - len(b64) % 4) % 4)
                d    = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
                return bool(d.get("add") and d.get("port"))
            # ss:// می‌تواند base64-encoded (ss://BASE64#name) یا plaintext
            # (ss://method:pass@host:port) باشد — هر دو باید معتبر شناخته شوند.
            if lower.startswith("ss://"):
                return "@" in s or ":" in s
            if lower.startswith(("hysteria2://","hy2://")):
                return "@" in s
            # رفع درخواست «فیلتر پروتکل قوی‌تر»: پشتیبانی از hysteria نسخه‌ی ۱
            # (متفاوت از hysteria2 — فرمت URI مشابه اما اسکیم متفاوت است).
            if lower.startswith("hysteria://"):
                return "@" in s or ":" in s
            if lower.startswith(("wireguard://","wg://")):
                return "@" in s or ":" in s
            # ShadowsocksR — فرمت ssr://BASE64 است؛ کل بخش بعد از اسکیم باید
            # base64 معتبر باشد (حتی اگر محتوایش را کامل پارس نکنیم، حداقل
            # باید decode شود تا مطمئن شویم رشته‌ی بی‌معنی نیست).
            if lower.startswith("ssr://"):
                b64 = s[6:].strip()
                b64 += "=" * ((4 - len(b64) % 4) % 4)
                try:
                    base64.b64decode(b64, validate=False)
                    return len(b64) > 8
                except Exception:
                    return False
            # SOCKS5 با احراز هویت: socks://user:pass@host:port یا بدون auth.
            # باید بعد از «://» حداقل یک «:» دیگر (برای پورت) وجود داشته باشد
            # — صرفِ وجود «:» در رشته کافی نیست چون خودِ «://» همیشه یک «:»
            # دارد.
            if lower.startswith("socks://"):
                return ":" in s[8:]
            # NaiveProxy: naive+https://user:pass@host:port
            if lower.startswith("naive"):
                return "@" in s and ":" in s
            # Snell: snell://psk@host:port یا snell://base64
            if lower.startswith("snell://"):
                return "@" in s or ":" in s
        except Exception:
            return False
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# ConfigReputation — سیستم اعتبار کانفیگ
# ═══════════════════════════════════════════════════════════════════════════════
class ConfigReputation:
    """
    ذخیره success/fail برای هر config_hash.
    کاربران می‌توانند کانفیگ معیوب گزارش دهند.

    رفع باگ «رشد بی‌نهایت حافظه»: قبلاً _cache یک dict معمولی بود که هیچ‌گاه
    پاک‌سازی نمی‌شد — با هر گزارش کاربر یک رکورد جدید اضافه می‌شد و با گذشت
    زمان کل حافظه‌ی بات را پر می‌کرد (OOM). حالا از OrderedDict به‌عنوان یک
    LRU cache با سقف Config.REPUTATION_MAX_ENTRIES استفاده می‌شود: هر بار که
    یک ورودی خوانده یا نوشته می‌شود به انتهای صف منتقل می‌شود (most-recently
    used)، و اگر تعداد از سقف رد شود، قدیمی‌ترین/کم‌استفاده‌ترین ورودی‌ها حذف
    می‌شوند.
    """
    _cache: "OrderedDict" = OrderedDict()   # config_hash → {success, fail, reports}

    @classmethod
    def _touch(cls, config_hash: str) -> dict:
        if config_hash in cls._cache:
            cls._cache.move_to_end(config_hash)
            return cls._cache[config_hash]
        entry = {"success": 0, "fail": 0, "reports": 0}
        cls._cache[config_hash] = entry
        while len(cls._cache) > Config.REPUTATION_MAX_ENTRIES:
            cls._cache.popitem(last=False)   # حذف قدیمی‌ترین ورودی
        return entry

    @classmethod
    def record_report(cls, config_hash: str) -> None:
        e = cls._touch(config_hash)
        e["reports"] += 1
        e["fail"]    += 1

    @classmethod
    def record_success(cls, config_hash: str) -> None:
        e = cls._touch(config_hash)
        e["success"] += 1

    @classmethod
    def get(cls, config_hash: str) -> dict:
        if config_hash in cls._cache:
            cls._cache.move_to_end(config_hash)
            return cls._cache[config_hash]
        return {"success": 0, "fail": 0, "reports": 0}

    @classmethod
    def reliability(cls, config_hash: str) -> float:
        e     = cls.get(config_hash)
        total = e["success"] + e["fail"]
        return round(e["success"] / total * 100, 1) if total else 100.0


# ═══════════════════════════════════════════════════════════════════════════════
# System Metrics — CPU / RAM / disk
# ═══════════════════════════════════════════════════════════════════════════════
_START_TIME   = time.time()
_prev_cpu     = {"idle": 0, "total": 0, "ts": 0.0}

def _read_mem_mb() -> float:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except Exception:
        pass
    return 0.0

def _read_container_cpu_ns() -> "tuple[float, float]|None":
    """
    زمان CPU مصرف‌شده توسط خودِ کانتینر (نه کل سرور میزبان) را از cgroups
    می‌خواند. cgroup v2 (فایل واحد cpu.stat) و cgroup v1 (cpuacct.usage) هر دو
    پشتیبانی می‌شوند. اگر هیچ‌کدام در دسترس نبود، None برمی‌گرداند تا کد فراخوان
    به /proc/stat (سراسر سرور) بازگردد.
    برمی‌گرداند: (usage_seconds, wall_clock_seconds) یا None.
    """
    # cgroup v2
    try:
        with open("/sys/fs/cgroup/cpu.stat") as f:
            for line in f:
                if line.startswith("usage_usec"):
                    usage_usec = int(line.split()[1])
                    return usage_usec / 1_000_000, time.monotonic()
    except Exception:
        pass
    # cgroup v1
    try:
        with open("/sys/fs/cgroup/cpu/cpuacct.usage") as f:
            usage_ns = int(f.read().strip())
            return usage_ns / 1_000_000_000, time.monotonic()
    except Exception:
        pass
    return None


def _read_cgroup_cpu_quota() -> "float|None":
    """تعداد هسته‌های تخصیص‌یافته به کانتینر (cpu.max یا cfs_quota/period)."""
    try:
        with open("/sys/fs/cgroup/cpu.max") as f:
            quota_s, period_s = f.read().split()
            if quota_s == "max":
                return None
            return int(quota_s) / int(period_s)
    except Exception:
        pass
    try:
        with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") as f:
            quota = int(f.read().strip())
        with open("/sys/fs/cgroup/cpu/cpu.cfs_period_us") as f:
            period = int(f.read().strip())
        if quota <= 0:
            return None
        return quota / period
    except Exception:
        return None


def _read_cpu_percent() -> float:
    """
    درصد CPU مصرفی — ابتدا تلاش می‌کند از cgroup (مخصوص خودِ کانتینر) بخواند
    که روی پلتفرم‌هایی مثل Railway دقیق‌تر از /proc/stat (که کل سرور میزبان را
    نشان می‌دهد) است. اگر cgroup در دسترس نبود (مثلاً محیط غیرکانتینری)، به
    /proc/stat سراسری بازمی‌گردد.
    """
    cg = _read_container_cpu_ns()
    if cg is not None:
        usage_sec, now_mono = cg
        prev = _prev_cpu.get("cgroup")
        _prev_cpu["cgroup"] = {"usage": usage_sec, "ts": now_mono}
        if prev is None:
            return 0.0
        d_usage = usage_sec - prev["usage"]
        d_wall  = now_mono - prev["ts"]
        if d_wall <= 0:
            return 0.0
        quota_cores = _read_cgroup_cpu_quota() or 1.0
        pct = (d_usage / d_wall) / max(quota_cores, 0.01) * 100
        return round(min(pct, 100.0), 1)

    # Fallback: /proc/stat سراسری (فقط اگر cgroup اصلاً در دسترس نبود)
    try:
        with open("/proc/stat") as f:
            parts = f.readline().split()
        vals  = [int(x) for x in parts[1:]]
        total = sum(vals)
        idle  = vals[3] + (vals[4] if len(vals) > 4 else 0)
        prev  = _prev_cpu
        prev_total = prev.get("total", 0)
        prev_idle  = prev.get("idle", 0)
        dt    = total - prev_total
        di    = idle  - prev_idle
        prev["total"] = total; prev["idle"] = idle; prev["ts"] = time.time()
        if dt <= 0: return 0.0
        return round((1 - di / dt) * 100, 1)
    except Exception:
        return 0.0

def _format_uptime(sec: float) -> str:
    sec = int(sec)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, _   = divmod(rem, 60)
    return " ".join(filter(None, [f"{d}روز" if d else "", f"{h}ساعت" if h else "", f"{m}دقیقه"]))

def safe_truncate(text: str, max_len: int = 4000) -> str:
    if len(text) <= max_len: return text
    t = text[:max_len]
    if t.count("`") % 2: t += "`"
    return t + "\n\n`... (بریده شد)`"

# ═══════════════════════════════════════════════════════════════════════════════
# SmartNotifier — هشدارهای هوشمند به ادمین
# ═══════════════════════════════════════════════════════════════════════════════
class SmartNotifier:
    _last_notify: dict = {}
    _COOLDOWN = 1800   # 30 دقیقه بین هشدارهای مشابه

    @classmethod
    async def notify(cls, bot, key: str, msg: str) -> None:
        now = time.time()
        if now - cls._last_notify.get(key, 0) < cls._COOLDOWN:
            return
        cls._last_notify[key] = now
        try:
            await bot.send_message(Config.ADMIN_ID, msg, parse_mode="Markdown")
        except Exception:
            pass

    @classmethod
    async def check_all(cls, bot) -> None:
        # رفع باگ «وابستگی دایره‌ای»: قبلاً از __main__ ایمپورت می‌شد که فقط
        # وقتی این فایل مستقیماً به‌عنوان اسکریپت اصلی اجرا می‌شد کار می‌کرد و
        # نوشتن تست یا استفاده‌ی این کلاس‌ها به‌عنوان یک ماژول قابل import را
        # غیرممکن می‌کرد. چون CacheManager در همین فایل (پایین‌تر) تعریف شده،
        # و این متد فقط زمان فراخوانی واقعی اجرا می‌شود (نه در زمان تعریف
        # کلاس)، پایتون نام CacheManager را در scope سراسری همین ماژول به‌طور
        # طبیعی resolve می‌کند — نیازی به import صریح نیست.
        cache_size = len(CacheManager._cache)
        mem_mb     = _read_mem_mb()
        cpu_pct    = _read_cpu_percent()

        if cache_size < Config.MIN_CACHE_NOTIFY and cache_size > 0:
            await cls.notify(bot, "low_cache",
                f"⚠️ *هشدار کش*\n\nتعداد کانفیگ‌ها به `{cache_size:,}` رسید (کمتر از {Config.MIN_CACHE_NOTIFY:,})")
        if mem_mb > Config.MEM_ALERT_THRESHOLD / 100 * 1024:
            await cls.notify(bot, "high_mem",
                f"⚠️ *هشدار RAM*\n\nمصرف حافظه: `{mem_mb:.1f} MB`")
        if cpu_pct > Config.CPU_ALERT_THRESHOLD:
            await cls.notify(bot, "high_cpu",
                f"⚠️ *هشدار CPU*\n\nمصرف پردازنده: `{cpu_pct:.1f}%`")

# ═══════════════════════════════════════════════════════════════════════════════
# RuleEngine — موتور قوانین ساده  IF condition THEN action
# ═══════════════════════════════════════════════════════════════════════════════
class RuleEngine:
    """
    قوانین از DB لود می‌شوند. فرمت شرط:
      cache_size < N   →  reload
      mem_mb > N       →  clear_cache
      error_rate > N   →  notify_admin
    """
    @classmethod
    async def evaluate_all(cls, bot) -> None:
        # رفع باگ وابستگی دایره‌ای — توضیح کامل در SmartNotifier.check_all.
        try:
            rules = await DatabaseManager.get_rules()
        except Exception:
            return
        mem   = _read_mem_mb()
        cache = len(CacheManager._cache)
        for rule in rules:
            if not rule["enabled"]: continue
            try:
                cond   = rule["condition"].strip()
                action = rule["action"].strip()
                if not cls._eval(cond, cache_size=cache, mem_mb=mem):
                    continue
                await cls._act(action, bot, cache, mem)
                await DatabaseManager.touch_rule(rule["id"])
            except Exception:
                pass

    @classmethod
    def _eval(cls, cond: str, **ctx) -> bool:
        # هر شرط فقط از مقایسه‌های ساده پشتیبانی می‌کند: var op value
        m = re.match(r"(\w+)\s*([<>=!]+)\s*([0-9.]+)", cond)
        if not m: return False
        var, op, val = m.group(1), m.group(2), float(m.group(3))
        lv = float(ctx.get(var, 0))
        return {"<": lv<val, ">": lv>val, "<=": lv<=val, ">=": lv>=val,
                "==": lv==val, "!=": lv!=val}.get(op, False)

    @classmethod
    async def _act(cls, action: str, bot, cache, mem) -> None:
        # رفع باگ وابستگی دایره‌ای — توضیح کامل در SmartNotifier.check_all.
        a = action.strip().lower()
        if a == "reload":
            asyncio.create_task(CacheManager.reload())
        elif a == "clear_cache":
            async with CacheManager._get_lock():
                half = len(CacheManager._cache) // 2
                CacheManager._cache = CacheManager._cache[:half]
        elif a == "notify_admin":
            await SmartNotifier.notify(bot, f"rule_{action}",
                f"⚙️ *Rule Engine*\n`{action}` اجرا شد — کش: {cache:,} | RAM: {mem:.0f}MB")

# ═══════════════════════════════════════════════════════════════════════════════
# AnomalyDetector — تشخیص انحراف ناگهانی
# ═══════════════════════════════════════════════════════════════════════════════
class AnomalyDetector:
    _prev_cache = 0
    _prev_source_fail = 0

    @classmethod
    async def check(cls, bot, new_cache: int, source_fail_count: int) -> None:
        # افت ناگهانی بیش از ۵۰٪ کانفیگ
        if cls._prev_cache > 0 and new_cache < cls._prev_cache * 0.5:
            await SmartNotifier.notify(bot, "anomaly_cache",
                f"🚨 *Anomaly: افت شدید کانفیگ*\n{cls._prev_cache:,} → {new_cache:,}")
        # بیش از ۷۰٪ منابع ناموفق
        if source_fail_count > 5 and cls._prev_source_fail == 0:
            await SmartNotifier.notify(bot, "anomaly_sources",
                f"🚨 *Anomaly: {source_fail_count} منبع ناموفق*")
        cls._prev_cache       = new_cache
        cls._prev_source_fail = source_fail_count


# ═══════════════════════════════════════════════════════════════════════════════
# DatabaseManager — مدیریت SQLite با صف نوشتن
# ═══════════════════════════════════════════════════════════════════════════════
class DatabaseManager:
    _conn:        "aiosqlite.Connection | None" = None
    _write_queue: "asyncio.Queue | None"        = None
    _worker_task: "asyncio.Task | None"         = None

    # ── اتصال ──────────────────────────────────────────────────────────────────
    @classmethod
    async def get_conn(cls) -> "aiosqlite.Connection":
        if cls._conn is None:
            cls._conn = await aiosqlite.connect(Config.DB_PATH)
            for pragma in ["PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL",
                           "PRAGMA cache_size=-8000", "PRAGMA busy_timeout=5000"]:
                await cls._conn.execute(pragma)
            cls._conn.row_factory = aiosqlite.Row
        return cls._conn

    # ── صف نوشتن ────────────────────────────────────────────────────────────────
    # نکته دربارهٔ رفع باگ «از دست رفتن داده در صف نوشتن»: قبلاً وقتی صف اصلی
    # (ظرفیت ۴۰۹۶) پر می‌شد، put_nowait با QueueFull مواجه می‌شد و آیتم فقط با
    # یک لاگ هشدار به‌کلی دور ریخته می‌شد — یعنی آمار مصرف، فیدبک و رویدادهای
    # مهم در پیک بار برای همیشه گم می‌شدند. حالا یک بافر overflow محدود (deque)
    # اضافه شده: اگر صف اصلی پر باشد، آیتم به‌جای دور ریختن در این بافر می‌ماند
    # و worker همیشه قبل از گرفتن آیتم جدید از صف، ابتدا overflow را خالی
    # می‌کند. فقط اگر خودِ overflow هم پر شود (فشار پایدار و غیرعادی، نه یک
    # پیک لحظه‌ای) آیتم دور ریخته می‌شود و شمارنده‌ی dropped برای دیده‌شدن در
    # /health افزایش می‌یابد.
    _overflow:      "list|None" = None
    _dropped_count: int = 0
    _OVERFLOW_MAX:  int = 20000

    @classmethod
    def _get_queue(cls) -> "asyncio.Queue":
        if cls._write_queue is None:
            cls._write_queue = asyncio.Queue(maxsize=4096)
        return cls._write_queue

    @classmethod
    def _get_overflow(cls) -> list:
        if cls._overflow is None:
            cls._overflow = []
        return cls._overflow

    @classmethod
    async def start_write_worker(cls) -> None:
        cls._worker_task = asyncio.create_task(cls._write_worker(), name="db-write-worker")
        logger.info("⚙️  DB write-worker آماده.")

    @classmethod
    async def _write_worker(cls) -> None:
        q = cls._get_queue()
        while True:
            # ابتدا هر آیتمی که به‌خاطر پر بودن صف در overflow جا مانده را
            # به صف اصلی برمی‌گردانیم (اگر جا باز شده باشد) تا هیچ نوشتنی
            # جا نماند.
            overflow = cls._get_overflow()
            while overflow and not q.full():
                q.put_nowait(overflow.pop(0))

            first = await q.get()
            batch = [first]
            for _ in range(49):
                try:    batch.append(q.get_nowait())
                except asyncio.QueueEmpty: break
            db = await cls.get_conn()
            try:
                for sql, params in batch: await db.execute(sql, params)
                await db.commit()
            except Exception as exc:
                logger.error(f"DB write-worker: خطای دسته‌ای، تلاش مجدد تک‌به‌تک: {exc}")
                try: await db.rollback()
                except Exception: pass
                # Fallback فردی: تراکنش‌های سالم را از دست ندهیم — فقط چون یک
                # آیتم خراب (مثلاً نقض UNIQUE) کل batch را fail کرده، بقیه‌ی
                # ۴۹ نوشتن سالم دیگر نباید قربانی شوند.
                ok_count, fail_count = 0, 0
                for sql, params in batch:
                    try:
                        await db.execute(sql, params)
                        await db.commit()
                        ok_count += 1
                    except Exception as item_exc:
                        fail_count += 1
                        try: await db.rollback()
                        except Exception: pass
                        logger.warning(f"DB write (individual) ناموفق: {sql[:60]}... — {item_exc}")
                logger.info(f"DB write-worker fallback: {ok_count} موفق، {fail_count} ناموفق از {len(batch)}")
            finally:
                for _ in batch: q.task_done()

    @classmethod
    def _enqueue(cls, sql: str, params: tuple) -> None:
        try:
            cls._get_queue().put_nowait((sql, params))
        except asyncio.QueueFull:
            overflow = cls._get_overflow()
            if len(overflow) < cls._OVERFLOW_MAX:
                overflow.append((sql, params))
                logger.warning(
                    f"صف اصلی DB پر — به overflow منتقل شد ({len(overflow)}/{cls._OVERFLOW_MAX}): {sql[:50]}")
            else:
                # فقط وقتی هم صف اصلی و هم overflow (جمعاً ~۲۴٬۰۰۰ نوشتن در
                # صف انتظار) پر باشند به این نقطه می‌رسیم — یعنی فشار پایدار
                # غیرعادی، نه یک پیک معمولی. اینجا واقعاً باید دور بریزیم تا
                # از مصرف بی‌نهایت حافظه جلوگیری شود، ولی این رویداد را
                # می‌شمریم تا در /health دیده شود.
                cls._dropped_count += 1
                logger.error(
                    f"⚠️ صف DB و overflow هر دو پر — نوشتن دور ریخته شد "
                    f"(مجموع دورریز: {cls._dropped_count}): {sql[:50]}")

    @classmethod
    def get_write_queue_health(cls) -> dict:
        """برای نمایش در /health — وضعیت صف نوشتن دیتابیس."""
        q = cls._write_queue
        return {
            "queue_size":    q.qsize() if q else 0,
            "overflow_size": len(cls._get_overflow()),
            "dropped_total": cls._dropped_count,
        }

    # ── init_db ─────────────────────────────────────────────────────────────────
    @staticmethod
    async def init_db() -> None:
        db = await DatabaseManager.get_conn()
        stmts = [
            """CREATE TABLE IF NOT EXISTS prefs (
                user_id        INTEGER PRIMARY KEY,
                protocol       TEXT    NOT NULL DEFAULT 'ALL',
                country        TEXT    NOT NULL DEFAULT 'ALL',
                language       TEXT    NOT NULL DEFAULT 'fa',
                is_vip         INTEGER NOT NULL DEFAULT 0,
                user_state     TEXT,
                username       TEXT, first_name TEXT,
                first_seen     TEXT, last_seen  TEXT,
                total_downloads INTEGER NOT NULL DEFAULT 0,
                fav_country    TEXT    NOT NULL DEFAULT 'ALL',
                fav_protocol   TEXT    NOT NULL DEFAULT 'ALL'
            )""",
            """CREATE TABLE IF NOT EXISTS sources (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                url            TEXT    UNIQUE NOT NULL,
                enabled        INTEGER NOT NULL DEFAULT 1,
                fail_count     INTEGER NOT NULL DEFAULT 0,
                last_fail_time REAL    NOT NULL DEFAULT 0,
                datacenter     TEXT    DEFAULT 'Unknown',
                found_via      TEXT    DEFAULT 'manual'
            )""",
            """CREATE TABLE IF NOT EXISTS daily_usage (
                user_id          INTEGER NOT NULL,
                date             TEXT    NOT NULL,
                requests_count   INTEGER NOT NULL DEFAULT 0,
                configs_received INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, date)
            )""",
            """CREATE TABLE IF NOT EXISTS banned_users (
                user_id   INTEGER PRIMARY KEY,
                banned_at TEXT NOT NULL, reason TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS ip_blacklist (
                ip        TEXT PRIMARY KEY,
                reason    TEXT, added_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS user_feedback (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                config_hash TEXT    NOT NULL,
                reason      TEXT,
                timestamp   TEXT    NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS abuse_scores (
                user_id      INTEGER PRIMARY KEY,
                score        INTEGER NOT NULL DEFAULT 0,
                warn_count   INTEGER NOT NULL DEFAULT 0,
                mute_until   TEXT,
                last_updated TEXT    NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS system_logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                level     TEXT NOT NULL,
                source    TEXT,
                message   TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS rules (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL,
                condition    TEXT NOT NULL,
                action       TEXT NOT NULL,
                enabled      INTEGER NOT NULL DEFAULT 1,
                last_triggered TEXT,
                created_at   TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS github_sources (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                url        TEXT UNIQUE NOT NULL,
                repo       TEXT NOT NULL,
                stars      INTEGER DEFAULT 0,
                found_at   TEXT NOT NULL,
                notified   INTEGER DEFAULT 0
            )""",
            """CREATE TABLE IF NOT EXISTS search_cooldown (
                user_id    INTEGER PRIMARY KEY,
                last_search REAL NOT NULL DEFAULT 0
            )""",
            # جدول تنظیمات عمومی key-value — برای سوییچ‌های روشن/خاموش قابل‌تغییر
            # توسط ادمین از داخل پنل، بدون نیاز به تغییر متغیر محیطی و ری‌استارت بات.
            """CREATE TABLE IF NOT EXISTS bot_settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_daily     ON daily_usage(user_id, date)",
            "CREATE INDEX IF NOT EXISTS idx_logs_ts   ON system_logs(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_feedback  ON user_feedback(config_hash)",
            # رفع باگ #1 (کوئری‌های سنگین پنل ادمین بدون ایندکس مناسب): این سه
            # ایندکس دقیقاً روی ستون‌هایی هستند که پنل ادمین با ORDER BY/WHERE
            # روی آن‌ها اسکن کامل جدول prefs انجام می‌داد — «Top کاربران»
            # (ORDER BY total_downloads)، لیست کاربران فعال/غیرفعال
            # (WHERE/ORDER BY last_seen) و لیست VIP (WHERE is_vip=1). بدون این
            # ایندکس‌ها SQLite مجبور بود روی کل جدول prefs (که با رشد کاربران
            # می‌تواند خیلی بزرگ شود) اسکن و sort کامل انجام دهد.
            "CREATE INDEX IF NOT EXISTS idx_prefs_downloads ON prefs(total_downloads DESC)",
            "CREATE INDEX IF NOT EXISTS idx_prefs_lastseen  ON prefs(last_seen)",
            "CREATE INDEX IF NOT EXISTS idx_prefs_vip       ON prefs(is_vip)",
        ]
        for stmt in stmts:
            await db.execute(stmt)
        # migrate existing prefs if needed
        for col, decl in [
            ("language","TEXT NOT NULL DEFAULT 'fa'"),("is_vip","INTEGER NOT NULL DEFAULT 0"),
            ("user_state","TEXT"),("first_name","TEXT"),("total_downloads","INTEGER NOT NULL DEFAULT 0"),
            ("fav_country","TEXT NOT NULL DEFAULT 'ALL'"),("fav_protocol","TEXT NOT NULL DEFAULT 'ALL'"),
        ]:
            try: await db.execute(f"ALTER TABLE prefs ADD COLUMN {col} {decl}")
            except Exception: pass
        # طبق درخواست صریح ادمین، سیستم Real Ping Tester کامل حذف شد. برای
        # نصب‌هایی که از قبل در حال اجرا بودند (که دقیقاً همین بات است)،
        # جدول قدیمی tested_configs ممکن است هنوز فیزیکاً در فایل دیتابیس
        # وجود داشته باشد — این‌جا صریحاً حذفش می‌کنیم تا فضای دیتابیس آزاد
        # شود و چیزی بلااستفاده باقی نماند.
        try: await db.execute("DROP TABLE IF EXISTS tested_configs")
        except Exception: pass
        await db.commit()
        logger.info("⚙️  دیتابیس آماده.")

    @staticmethod
    async def populate_default_sources() -> None:
        """
        رفع باگ «منابع درخواستی حذف/اضافه فقط روی نصب‌های تازه اعمال می‌شد»:
        قبلاً seed فقط وقتی جدول sources کاملاً خالی بود اجرا می‌شد — یعنی
        روی یک بات که از قبل در حال اجراست (که دقیقاً همان چیزی است که
        ادمین دارد)، تغییر DEFAULT_SOURCES/REMOVED_SOURCES در کد هیچ اثری
        روی دیتابیس واقعی نداشت. حالا این تابع همیشه (در هر استارتاپ) دو کار
        را انجام می‌دهد، مستقل از خالی یا پر بودن جدول:
          ۱) هر URL در REMOVED_SOURCES را به‌صورت قطعی از جدول حذف می‌کند.
          ۲) هر URL در DEFAULT_SOURCES که هنوز در جدول نیست را INSERT OR
             IGNORE می‌کند (بدون دست زدن به منابعی که ادمین بعداً دستی
             اضافه/حذف کرده).
        """
        db = await DatabaseManager.get_conn()

        if REMOVED_SOURCES:
            placeholders = ",".join("?" for _ in REMOVED_SOURCES)
            cur = await db.execute(
                f"DELETE FROM sources WHERE url IN ({placeholders})", REMOVED_SOURCES)
            if cur.rowcount:
                logger.info(f"🗑 {cur.rowcount} منبع منسوخ (REMOVED_SOURCES) از دیتابیس حذف شد.")

        await db.executemany(
            "INSERT OR IGNORE INTO sources (url,enabled) VALUES (?,1)",
            [(u,) for u in DEFAULT_SOURCES])
        await db.commit()
        logger.info(f"✅ بررسی منابع پیش‌فرض کامل شد ({len(DEFAULT_SOURCES)} URL بررسی شد).")

    # ── تنظیمات عمومی (key-value) — سوییچ‌های روشن/خاموش قابل‌تغییر از پنل ──────
    @staticmethod
    async def get_setting(key: str, default: str = "") -> str:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT value FROM bot_settings WHERE key=?", (key,)) as cur:
            row = await cur.fetchone()
            return row[0] if row else default

    @staticmethod
    async def set_setting(key: str, value: str) -> None:
        db = await DatabaseManager.get_conn()
        await db.execute(
            "INSERT INTO bot_settings (key,value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        await db.commit()

    # طبق درخواست صریح ادمین: سیستم آرشیو کانفیگ‌های حذف‌شده کامل حذف شد،
    # چون بی‌نیاز شده — دیگر هیچ فیلتر کیفیتی کانفیگ رد نمی‌کند تا چیزی
    # برای آرشیو کردن وجود داشته باشد. تنها دلیل باقی‌مانده‌ی رد یک کانفیگ،
    # نامعتبر بودن ساختاری آن است (که واقعاً قابل استفاده نیست) یا مسدود
    # بودن IP آن توسط ادمین.

    # ── prefs ──────────────────────────────────────────────────────────────────
    @staticmethod
    async def get_user_prefs(user_id: int) -> dict:
        db = await DatabaseManager.get_conn()
        await db.execute("INSERT OR IGNORE INTO prefs (user_id) VALUES (?)",(user_id,))
        await db.commit()
        async with db.execute(
            "SELECT protocol,country,language,is_vip,user_state,total_downloads,"
            "fav_country,fav_protocol FROM prefs WHERE user_id=?", (user_id,)
        ) as cur:
            r = await cur.fetchone()

        if r is None:
            # رفع باگ «احتمال خطای NoneType»: قبلاً اگر به هر دلیلی (مثلاً
            # race condition بین چند درخواست همزمان، یا یک خطای گذرای DB)
            # INSERT OR IGNORE سطر را واقعاً ننوشته بود، SELECT بعدی None
            # برمی‌گرداند و r[0] بلافاصله با TypeError کرش می‌کرد. حالا یک
            # بار دیگر INSERT+SELECT تلاش می‌شود (برای رفع race condition
            # لحظه‌ای)؛ اگر باز هم ناموفق بود، به‌جای کرش، مقادیر پیش‌فرض
            # امن (همان مقادیر DEFAULT جدول prefs) برگردانده می‌شود تا کاربر
            # حداقل بتواند با بات کار کند.
            logger.warning(f"get_user_prefs: ردیف prefs برای user_id={user_id} یافت نشد — تلاش مجدد.")
            await db.execute("INSERT OR IGNORE INTO prefs (user_id) VALUES (?)",(user_id,))
            await db.commit()
            async with db.execute(
                "SELECT protocol,country,language,is_vip,user_state,total_downloads,"
                "fav_country,fav_protocol FROM prefs WHERE user_id=?", (user_id,)
            ) as cur:
                r = await cur.fetchone()

        if r is None:
            logger.error(f"get_user_prefs: تلاش مجدد هم ناموفق بود برای user_id={user_id} — پیش‌فرض امن استفاده شد.")
            return {
                "protocol": "ALL", "country": "ALL", "language": "fa",
                "is_vip": False, "user_state": None,
                "total_downloads": 0,
                "fav_country": "ALL", "fav_protocol": "ALL",
            }

        return {
            "protocol": r[0], "country": r[1], "language": r[2] or "fa",
            "is_vip": bool(r[3]), "user_state": r[4],
            "total_downloads": r[5] or 0,
            "fav_country": r[6] or "ALL", "fav_protocol": r[7] or "ALL",
        }

    @staticmethod
    async def set_user_pref(user_id: int, key: str, value) -> None:
        _SQL = {
            "protocol":       "UPDATE prefs SET protocol=?       WHERE user_id=?",
            "country":        "UPDATE prefs SET country=?        WHERE user_id=?",
            "language":       "UPDATE prefs SET language=?       WHERE user_id=?",
            "is_vip":         "UPDATE prefs SET is_vip=?         WHERE user_id=?",
            "user_state":     "UPDATE prefs SET user_state=?     WHERE user_id=?",
            "fav_country":    "UPDATE prefs SET fav_country=?    WHERE user_id=?",
            "fav_protocol":   "UPDATE prefs SET fav_protocol=?   WHERE user_id=?",
        }
        if key not in _SQL: raise ValueError(f"کلید نامعتبر: {key!r}")
        db = await DatabaseManager.get_conn()
        await db.execute("INSERT OR IGNORE INTO prefs (user_id) VALUES (?)",(user_id,))
        await db.execute(_SQL[key],(int(value) if isinstance(value,bool) else value, user_id))
        await db.commit()

    # ── usage ──────────────────────────────────────────────────────────────────
    @staticmethod
    async def check_rate_limit(user_id: int) -> tuple:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        db    = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT requests_count,configs_received FROM daily_usage WHERE user_id=? AND date=?",
            (user_id,today)
        ) as cur:
            r = await cur.fetchone()
            return (r[0],r[1]) if r else (0,0)

    @staticmethod
    async def increment_usage(user_id: int, count: int) -> None:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        DatabaseManager._enqueue(
            """INSERT INTO daily_usage (user_id,date,requests_count,configs_received)
               VALUES (?,?,1,?) ON CONFLICT(user_id,date) DO UPDATE SET
               requests_count=requests_count+1,configs_received=configs_received+?""",
            (user_id,today,count,count))
        DatabaseManager._enqueue(
            "UPDATE prefs SET total_downloads=total_downloads+? WHERE user_id=?",(count,user_id))

    @staticmethod
    async def touch_user(user_id: int, username: "str|None", first_name: "str|None" = None) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        DatabaseManager._enqueue(
            "INSERT OR IGNORE INTO prefs (user_id,first_seen) VALUES (?,?)",(user_id,now))
        DatabaseManager._enqueue(
            "UPDATE prefs SET username=?,first_name=?,last_seen=?,first_seen=COALESCE(first_seen,?) WHERE user_id=?",
            (username,first_name,now,now,user_id))

    # ── کاربران ────────────────────────────────────────────────────────────────
    @staticmethod
    async def count_total_users() -> int:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT COUNT(*) FROM prefs") as cur:
            return (await cur.fetchone())[0]

    @staticmethod
    async def get_all_user_ids() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT user_id FROM prefs") as cur:
            return [r[0] for r in await cur.fetchall()]

    @staticmethod
    async def get_active_users(days: int = 7) -> list:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        db     = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT user_id,username,first_name,last_seen FROM prefs WHERE last_seen>=? ORDER BY last_seen DESC",
            (cutoff,)
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def get_inactive_users(days: int = 30) -> list:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        db     = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT user_id,username,first_name,last_seen FROM prefs WHERE last_seen<? OR last_seen IS NULL ORDER BY last_seen",
            (cutoff,)
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def get_top_users(limit: int = 10) -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT p.user_id,p.username,p.first_name,p.total_downloads "
            "FROM prefs p ORDER BY p.total_downloads DESC LIMIT ?", (limit,)
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def get_user_full(user_id: int) -> "dict|None":
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT user_id,username,first_name,protocol,country,language,is_vip,"
            "first_seen,last_seen,total_downloads,fav_country,fav_protocol FROM prefs WHERE user_id=?",
            (user_id,)
        ) as cur:
            r = await cur.fetchone()
            if not r: return None
            return dict(zip([c[0] for c in cur.description], r))

    @staticmethod
    async def find_user(query: str) -> list:
        db = await DatabaseManager.get_conn()
        q  = f"%{query}%"
        async with db.execute(
            "SELECT user_id,username,first_name,last_seen FROM prefs WHERE username LIKE ? OR first_name LIKE ? OR CAST(user_id AS TEXT) LIKE ?",
            (q,q,q)
        ) as cur:
            return await cur.fetchall()

    # ── ban / VIP ───────────────────────────────────────────────────────────────
    @staticmethod
    async def ban_user(user_id: int, reason: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        db  = await DatabaseManager.get_conn()
        await db.execute("INSERT OR REPLACE INTO banned_users (user_id,banned_at,reason) VALUES (?,?,?)",(user_id,now,reason))
        await db.commit()

    @staticmethod
    async def unban_user(user_id: int) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT 1 FROM banned_users WHERE user_id=?",(user_id,)) as cur:
            if not await cur.fetchone(): return False
        await db.execute("DELETE FROM banned_users WHERE user_id=?",(user_id,))
        await db.commit()
        return True

    @staticmethod
    async def is_banned(user_id: int) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT 1 FROM banned_users WHERE user_id=?",(user_id,)) as cur:
            return bool(await cur.fetchone())

    @staticmethod
    async def get_banned_users() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT user_id,banned_at,reason FROM banned_users ORDER BY banned_at DESC") as cur:
            return await cur.fetchall()

    @staticmethod
    async def set_vip(user_id: int, status: bool) -> None:
        db = await DatabaseManager.get_conn()
        await db.execute("INSERT OR IGNORE INTO prefs (user_id) VALUES (?)",(user_id,))
        await db.execute("UPDATE prefs SET is_vip=? WHERE user_id=?",(1 if status else 0, user_id))
        await db.commit()

    @staticmethod
    async def get_vip_users() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT user_id,username,first_name,last_seen FROM prefs WHERE is_vip=1 ORDER BY last_seen DESC"
        ) as cur:
            return await cur.fetchall()

    # ── abuse ───────────────────────────────────────────────────────────────────
    @staticmethod
    async def get_abuse(user_id: int) -> dict:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT score,warn_count,mute_until FROM abuse_scores WHERE user_id=?",(user_id,)) as cur:
            r = await cur.fetchone()
            return {"score": r[0], "warn_count": r[1], "mute_until": r[2]} if r else {"score":0,"warn_count":0,"mute_until":None}

    @staticmethod
    async def update_abuse(user_id: int, score: int, warn_count: int, mute_until: "str|None") -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        DatabaseManager._enqueue(
            """INSERT INTO abuse_scores (user_id,score,warn_count,mute_until,last_updated) VALUES (?,?,?,?,?)
               ON CONFLICT(user_id) DO UPDATE SET score=?,warn_count=?,mute_until=?,last_updated=?""",
            (user_id,score,warn_count,mute_until,now, score,warn_count,mute_until,now))

    @staticmethod
    async def is_muted(user_id: int) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT mute_until FROM abuse_scores WHERE user_id=?",(user_id,)) as cur:
            r = await cur.fetchone()
            if not r or not r[0]: return False
        try:
            mu = datetime.fromisoformat(r[0]).replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) < mu
        except Exception:
            return False

    # ── IP blacklist ─────────────────────────────────────────────────────────────
    @staticmethod
    async def load_ip_blacklist() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT ip FROM ip_blacklist") as cur:
            return [r[0] for r in await cur.fetchall()]

    @staticmethod
    async def add_ip_blacklist(ip: str, reason: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        db  = await DatabaseManager.get_conn()
        await db.execute("INSERT OR IGNORE INTO ip_blacklist (ip,reason,added_at) VALUES (?,?,?)",(ip,reason,now))
        await db.commit()
        IPBlacklist.add(ip)

    @staticmethod
    async def get_ip_blacklist() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT ip,reason,added_at FROM ip_blacklist ORDER BY added_at DESC") as cur:
            return await cur.fetchall()

    # ── feedback ────────────────────────────────────────────────────────────────
    @staticmethod
    async def add_feedback(user_id: int, config_hash: str, reason: str) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        DatabaseManager._enqueue(
            "INSERT INTO user_feedback (user_id,config_hash,reason,timestamp) VALUES (?,?,?,?)",
            (user_id,config_hash,reason,now))
        ConfigReputation.record_report(config_hash)

    @staticmethod
    async def get_feedback(limit: int = 20) -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT uf.user_id,p.username,uf.config_hash,uf.reason,uf.timestamp "
            "FROM user_feedback uf LEFT JOIN prefs p ON uf.user_id=p.user_id ORDER BY uf.timestamp DESC LIMIT ?",
            (limit,)
        ) as cur:
            return await cur.fetchall()

    # ── منابع ───────────────────────────────────────────────────────────────────
    @staticmethod
    @staticmethod
    def _normalize_url(url: str) -> str:
        """
        رفع باگ #19 (عدم نرمال‌سازی URL در افزودن منبع): قبلاً URL ورودی
        دقیقاً همان‌طور که ادمین/GitHubSourceFinder وارد کرده بود ذخیره
        می‌شد، بدون هیچ نرمال‌سازی. در نتیجه دو URL که فقط در اسلش انتهایی
        فرق داشتند (مثلاً «https://x.com/sub» و «https://x.com/sub/») هر دو
        به‌عنوان منبع مجزا در جدول sources ثبت می‌شدند و باعث fetch تکراری
        و رکوردهای زائد می‌شدند — چون UNIQUE constraint جدول روی متن خام
        ستون url است، نه روی معنای واقعی URL.
        حالا پیش از هر INSERT، URL نرمال می‌شود: پروتکل و host به lowercase
        تبدیل می‌شوند (چون این‌ها case-insensitive هستند)، اسلش انتهایی از
        مسیر حذف می‌شود (مگر اینکه کل مسیر همان یک اسلش ریشه باشد) و
        fragment (#...) که هیچ نقشی در fetch ندارد کنار گذاشته می‌شود.
        query string دست‌نخورده می‌ماند چون می‌تواند برای برخی منابع معنادار
        باشد (مثلاً توکن یا نسخه).
        """
        try:
            parsed = urlparse(url.strip())
        except Exception:
            return url.strip()
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path   = parsed.path.rstrip("/") or "/"
        normalized = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    @staticmethod
    async def add_source(url: str, found_via: str = "manual") -> "tuple[bool, str]":
        """
        برمی‌گرداند (ok, reason). رفع باگ «لاگ‌نکردن موفقیت‌آمیز بودن افزودن
        منبع»: قبلاً هر خطایی (چه تکراری‌بودن URL چه خطای واقعی DB) با یک
        except Exception یکسان نادیده گرفته می‌شد و فقط True/False برمی‌گشت؛
        ادمین نمی‌فهمید مشکل واقعی چه بوده. حالا علت دقیق هم برگردانده و هم
        لاگ می‌شود.
        """
        url = SourceManager._normalize_url(url)
        try:
            dc = detect_datacenter(urlparse(url).netloc)
            db = await DatabaseManager.get_conn()
            await db.execute("INSERT INTO sources (url,enabled,datacenter,found_via) VALUES (?,1,?,?)",(url,dc,found_via))
            await db.commit()
            return True, "added"
        except aiosqlite.IntegrityError:
            logger.info(f"addsource: URL تکراری رد شد: {url}")
            return False, "duplicate"
        except Exception as exc:
            logger.error(f"addsource: خطای DB هنگام افزودن منبع {url}: {exc}", exc_info=True)
            return False, f"db_error: {exc}"

    @staticmethod
    async def remove_source(source_id: int) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT id FROM sources WHERE id=?",(source_id,)) as cur:
            if not await cur.fetchone(): return False
        await db.execute("DELETE FROM sources WHERE id=?",(source_id,))
        await db.commit()
        return True

    @staticmethod
    async def set_source_enabled(source_id: int, enabled: bool) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT id FROM sources WHERE id=?",(source_id,)) as cur:
            if not await cur.fetchone(): return False
        await db.execute("UPDATE sources SET enabled=? WHERE id=?",(1 if enabled else 0, source_id))
        await db.commit()
        return True

    @staticmethod
    async def get_all_sources() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT id,url,enabled,fail_count,last_fail_time,datacenter,found_via FROM sources ORDER BY id"
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def update_source_status(url: str, failed: bool) -> None:
        db = await DatabaseManager.get_conn()
        if failed:
            await db.execute("UPDATE sources SET fail_count=fail_count+1,last_fail_time=? WHERE url=?",(time.time(),url))
            await db.execute("UPDATE sources SET enabled=0 WHERE url=? AND fail_count>=3",(url,))
        else:
            await db.execute("UPDATE sources SET fail_count=0,last_fail_time=0,enabled=1 WHERE url=?",(url,))
        await db.commit()

    @staticmethod
    async def reenable_cooled_sources(cooldown: int = 1800) -> None:
        db = await DatabaseManager.get_conn()
        await db.execute("UPDATE sources SET enabled=1,fail_count=0 WHERE enabled=0 AND last_fail_time<?",(time.time()-cooldown,))
        await db.commit()

    @staticmethod
    async def get_top_sources(limit: int = 5) -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT id,url,fail_count,enabled,last_fail_time FROM sources ORDER BY fail_count ASC, enabled DESC LIMIT ?",
            (limit,)
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def get_slow_sources(limit: int = 5) -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT id,url,fail_count,enabled FROM sources ORDER BY fail_count DESC LIMIT ?", (limit,)
        ) as cur:
            return await cur.fetchall()

    # ── search cooldown ──────────────────────────────────────────────────────────
    @staticmethod
    async def check_search_cooldown(user_id: int) -> float:
        """برمی‌گرداند چند ثانیه باید صبر کند (0 = آزاد)."""
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT last_search FROM search_cooldown WHERE user_id=?",(user_id,)) as cur:
            r = await cur.fetchone()
            if not r: return 0.0
        elapsed = time.time() - r[0]
        wait    = Config.SEARCH_COOLDOWN - elapsed
        return max(0.0, wait)

    @staticmethod
    async def update_search_time(user_id: int) -> None:
        now = time.time()
        db  = await DatabaseManager.get_conn()
        await db.execute(
            "INSERT INTO search_cooldown (user_id,last_search) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET last_search=?",
            (user_id,now,now))
        await db.commit()

    # ── rules ────────────────────────────────────────────────────────────────────
    @staticmethod
    async def get_rules() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT id,name,condition,action,enabled,last_triggered FROM rules ORDER BY id") as cur:
            return [dict(zip([c[0] for c in cur.description], r)) for r in await cur.fetchall()]

    @staticmethod
    async def add_rule(name: str, condition: str, action: str) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        db  = await DatabaseManager.get_conn()
        await db.execute("INSERT INTO rules (name,condition,action,created_at) VALUES (?,?,?,?)",(name,condition,action,now))
        await db.commit()

    @staticmethod
    async def delete_rule(rule_id: int) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT id FROM rules WHERE id=?",(rule_id,)) as cur:
            if not await cur.fetchone(): return False
        await db.execute("DELETE FROM rules WHERE id=?",(rule_id,))
        await db.commit()
        return True

    @staticmethod
    async def touch_rule(rule_id: int) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        DatabaseManager._enqueue("UPDATE rules SET last_triggered=? WHERE id=?",(now,rule_id))

    # ── system logs ──────────────────────────────────────────────────────────────
    @staticmethod
    async def add_log(level: str, message: str, source: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        DatabaseManager._enqueue(
            "INSERT INTO system_logs (level,source,message,timestamp) VALUES (?,?,?,?)",
            (level,source,message,now))

    @staticmethod
    async def get_logs(limit: int = 30, level: str = "") -> list:
        db = await DatabaseManager.get_conn()
        if level:
            async with db.execute(
                "SELECT level,source,message,timestamp FROM system_logs WHERE level=? ORDER BY timestamp DESC LIMIT ?",
                (level,limit)
            ) as cur:
                return await cur.fetchall()
        else:
            async with db.execute(
                "SELECT level,source,message,timestamp FROM system_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            ) as cur:
                return await cur.fetchall()

    @staticmethod
    async def cleanup_logs(days: int = 7) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        db     = await DatabaseManager.get_conn()
        async with db.execute("SELECT COUNT(*) FROM system_logs WHERE timestamp<?",(cutoff,)) as cur:
            n = (await cur.fetchone())[0]
        await db.execute("DELETE FROM system_logs WHERE timestamp<?",(cutoff,))
        await db.commit()
        return n

    @staticmethod
    async def cleanup_github_sources(days: "int|None" = None) -> int:
        """
        رفع باگ #18 (رشد بی‌نهایت جدول github_sources): قبلاً این جدول هرگز
        پاک‌سازی نمی‌شد و با هر اجرای cron_github_search رکوردهای جدید
        (حتی برای URLهایی که دیگر منبع فعالی نیستند) به آن اضافه می‌شد،
        بدون سقف بالا. حالا رکوردهایی که هم قدیمی‌تر از
        GITHUB_SOURCES_MAX_AGE_DAYS هستند و هم قبلاً notified=1 شده‌اند
        (یعنی ادمین قبلاً اطلاع‌رسانی آن‌ها را دیده) پاک می‌شوند — رکوردهای
        notified=0 (هنوز دیده‌نشده) نگه داشته می‌شوند تا چیزی از دست ادمین
        در نرود.
        """
        days   = days if days is not None else Config.GITHUB_SOURCES_MAX_AGE_DAYS
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        db     = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT COUNT(*) FROM github_sources WHERE found_at<? AND notified=1",(cutoff,)
        ) as cur:
            n = (await cur.fetchone())[0]
        await db.execute("DELETE FROM github_sources WHERE found_at<? AND notified=1",(cutoff,))
        await db.commit()
        return n

    # ── GitHub sources ───────────────────────────────────────────────────────────
    @staticmethod
    async def save_github_source(url: str, repo: str, stars: int) -> bool:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            db = await DatabaseManager.get_conn()
            await db.execute(
                "INSERT OR IGNORE INTO github_sources (url,repo,stars,found_at) VALUES (?,?,?,?)",
                (url,repo,stars,now))
            await db.commit()
            return True
        except Exception:
            return False

    @staticmethod
    async def get_unnotified_github_sources() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT id,url,repo,stars,found_at FROM github_sources WHERE notified=0 ORDER BY stars DESC"
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def mark_github_notified(ids: list) -> None:
        if not ids: return
        db = await DatabaseManager.get_conn()
        await db.executemany("UPDATE github_sources SET notified=1 WHERE id=?",[(i,) for i in ids])
        await db.commit()

    # ── backup ───────────────────────────────────────────────────────────────────
    @staticmethod
    async def backup_db() -> bytes:
        import shutil, tempfile
        tmp = tempfile.mktemp(suffix=".db")
        db  = await DatabaseManager.get_conn()
        async with aiosqlite.connect(tmp) as dst:
            await db.backup(dst)
        with open(tmp, "rb") as f:
            data = f.read()
        os.unlink(tmp)
        return data

# ═══════════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════════
# SourceManager — دریافت و پردازش منابع
# ═══════════════════════════════════════════════════════════════════════════════
class SourceManager:
    # رفع درخواست «فیلتر پروتکل بسیار قوی‌تر شود»: نسخه‌ی قبلی فقط ۸ اسکیم را
    # می‌شناخت. اما منابع عمومی V2Ray/پروکسی معمولاً شامل چند اسکیم رایج دیگر
    # هم هستند که قبلاً اصلاً استخراج نمی‌شدند — یعنی نه فقط از دید فیلتر
    # پروتکل، بلکه از دید کل بات نامرئی بودند (هرگز حتی وارد کش هم نمی‌شدند).
    # حالا این اسکیم‌ها هم پوشش داده می‌شوند: hysteria (نسخه‌ی ۱، متفاوت از
    # hysteria2)، ssr (ShadowsocksR)، socks (پروکسی SOCKS5 با احراز هویت)،
    # naive (NaiveProxy)، snell (Snell).
    _CONFIG_RE = re.compile(
        r"(?:vless|vmess|trojan|ssr|ss|hysteria2|hysteria|hy2|tuic|"
        r"wireguard|wg|socks|naive(?:\+https?)?|snell)"
        r"://[^\s\n\r,\"'\]\[<>{}|\\^`]+", re.IGNORECASE)
    _ALIASES   = {"hy2": "hysteria2", "wg": "wireguard", "naive+https": "naive", "naive+http": "naive"}
    _semaphore: "asyncio.Semaphore|None" = None
    _MAX_B64   = 70 * 1024 * 1024
    _WS_TABLE  = str.maketrans("","","  \t\n\r\x0b\x0c")

    @classmethod
    def _get_sem(cls) -> asyncio.Semaphore:
        if cls._semaphore is None:
            cls._semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT_FETCHES)
        return cls._semaphore

    @staticmethod
    def extract_configs(text: str) -> list:
        return SourceManager._CONFIG_RE.findall(text)

    @staticmethod
    def try_decode_base64(raw: str) -> str:
        if len(raw) > SourceManager._MAX_B64: return ""
        cleaned = raw.translate(SourceManager._WS_TABLE)
        if len(cleaned) < 20 or not re.match(r"^[A-Za-z0-9+/=_-]+$", cleaned): return ""
        cleaned += "=" * ((4 - len(cleaned) % 4) % 4)
        last_err = None
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                return fn(cleaned.encode()).decode("utf-8", errors="ignore")
            except Exception as exc:
                last_err = exc
                continue
        # رفع باگ «مدیریت ناقص خطا در دیکود Base64»: قبلاً خطا کاملاً نادیده
        # گرفته می‌شد و فقط رشته‌ی خالی برمی‌گشت — هیچ ردی از علت شکست باقی
        # نمی‌ماند. حالا حداقل در سطح debug لاگ می‌شود (نه warning، چون این
        # تابع مرتب روی متن‌های غیر-base64 هم صدا زده می‌شود و لاگ سطح بالاتر
        # فقط نویز تولید می‌کند؛ برای دیباگ عمیق‌تر سطح لاگ را DEBUG کنید).
        logger.debug(f"try_decode_base64: دیکود ناموفق ({len(cleaned)} کاراکتر): {last_err}")
        return ""

    @staticmethod
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10), reraise=True)
    async def _fetch(session: aiohttp.ClientSession, url: str) -> str:
        ssl_ctx = False if Config.DISABLE_SSL_VERIFY else None
        if ssl_ctx is False:
            # رفع باگ SSL/MitM: قبلاً فقط یک بار در startup (Config.validate)
            # هشدار داده می‌شد. حالا هر بار که یک fetch واقعی بدون تأیید
            # گواهی انجام می‌شود جداگانه لاگ می‌شود تا در محیط تولید مشخص
            # باشد دقیقاً کدام درخواست‌ها بدون SSL verification رفته‌اند.
            logger.warning(f"⚠️ SSL verification غیرفعال — fetch بدون تأیید گواهی: {url}")
        timeout = aiohttp.ClientTimeout(total=Config.FETCH_TIMEOUT)
        async with session.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ConfigBot/6.0)"},
            timeout=timeout, ssl=ssl_ctx,
        ) as resp:
            if resp.status != 200: raise RuntimeError(f"HTTP {resp.status}")
            return await resp.text()

    @classmethod
    async def process_source(cls, session: aiohttp.ClientSession, url: str) -> "tuple[list,bool]":
        """
        برمی‌گرداند (items, failed). طبق درخواست صریح ادمین، هیچ فیلتر کیفیت
        سلیقه‌ای اعمال نمی‌شود — تنها دو دلیل رد یک کانفیگ باقی مانده: ساختار
        نامعتبر (واقعاً غیرقابل‌استفاده، مثل vmess با base64 خراب) یا IP که
        خودِ ادمین دستی مسدود کرده. کانفیگ‌های رد‌شده دیگر جایی نگه داشته
        نمی‌شوند (سیستم آرشیو هم به همین دلیل حذف شد).
        """
        async with cls._get_sem():
            try:
                text     = await cls._fetch(session, url)
                raw_cfgs = cls.extract_configs(text)
                decoded  = cls.try_decode_base64(text)
                if decoded: raw_cfgs.extend(cls.extract_configs(decoded))

                results: list = []
                seen: set     = set()
                fps:  set     = set()   # fingerprint dedup

                for raw in raw_cfgs:
                    if raw in seen: continue
                    seen.add(raw)
                    if not ConfigStructureValidator.is_valid(raw):
                        continue
                    # طبق درخواست صریح ادمین، فیلتر کیفیت سلیقه‌ای (طول رشته،
                    # تشخیص honeypot، و غیره) کاملاً حذف شده است. تنها بررسی
                    # باقی‌مانده IPBlacklist است که یک قابلیت مدیریتی جداست —
                    # لیستی که خودِ ادمین دستی IP اضافه/حذف می‌کند، نه یک
                    # فیلتر خودکار روی محتوای کانفیگ.
                    if IPBlacklist.config_is_blocked(raw):
                        continue
                    fp = AdvancedDeduplicator.fingerprint(raw)
                    if fp in fps: continue
                    fps.add(fp)
                    proto_guess = raw.split("://")[0].lower()
                    proto   = cls._ALIASES.get(proto_guess, proto_guess)
                    country = CountryDetector.detect(raw)
                    # رفع باگ‌های #11-#15: proto/country باید پیش از فراخوانی
                    # BrandingEngine.apply محاسبه شوند تا در صورت نبود نام
                    # اصلی در خودِ کانفیگ، بشود یک نام پیش‌فرض مفید (پرچم +
                    # کشور + پروتکل) ساخت، به‌جای رها کردن کانفیگ بدون اسم.
                    branded = BrandingEngine.apply(raw, country=country, protocol=proto)
                    hp_match = AdvancedDeduplicator._HOST_PORT_RE.search(raw)
                    dc       = detect_datacenter(hp_match.group(1) if hp_match else url)
                    results.append({"config": branded, "protocol": proto,
                                    "country": country, "dc": dc, "fp": fp})

                await DatabaseManager.update_source_status(url, failed=False)
                return results, False

            except Exception as exc:
                logger.warning(f"❌ منبع ناموفق [{url}]: {type(exc).__name__}: {exc}")
                await DatabaseManager.update_source_status(url, failed=True)
                return [], True

# ═══════════════════════════════════════════════════════════════════════════════
# CacheManager — مدیریت کش کانفیگ‌ها
# ═══════════════════════════════════════════════════════════════════════════════
class CacheManager:
    _cache:       list = []
    _last_update: str  = "هنوز بروزرسانی نشده"
    _prev_count:  int  = 0
    _prev_delta:  str  = ""
    is_loading:   bool = True
    _lock: "asyncio.Lock|None" = None
    _global_fps:  set = set()   # fingerprints of all cached configs
    _last_reload_mono: float = 0.0   # monotonic ts — برای جلوگیری از reload تکراری همزمان

    # رفع باگ #3 (اسکن کامل کش در توابع آماری): قبلاً stats()، count_filtered()
    # و count_search() هر بار که فراخوانی می‌شدند (یعنی هر بار کاربر روی دکمه‌ی
    # پنل ادمین یا دکمه‌ی دریافت کانفیگ می‌زد) کل کش را (تا ۵۰٬۰۰۰ آیتم) به‌طور
    # سینک روی event loop می‌پیمودند. چون این حلقه sync است، در طول اجرایش کل
    # event loop بلاک می‌شود و هیچ درخواست دیگری (حتی از کاربران دیگر) پردازش
    # نمی‌شود؛ با چند درخواست همزمان این بلاک‌شدن‌ها روی هم جمع می‌شوند و پنل
    # ادمین را بی‌پاسخ نشان می‌دهند. حالا یک ایندکس آماری (بر اساس پروتکل و
    # کشور) فقط یک‌بار در پایان reload() ساخته می‌شود؛ stats/count_filtered
    # به‌جای پیمایش کامل کش، از این ایندکس آماده (O(1) یا O(تعداد گروه‌ها)
    # به‌جای O(کل کش)) استفاده می‌کنند.
    _proto_country_index: dict = {}   # (protocol, country) → count
    _proto_totals:        dict = {}   # protocol → count
    _country_totals:      dict = {}   # country  → count
    _dc_totals:           dict = {}   # datacenter → count

    @classmethod
    def _rebuild_stats_index(cls) -> None:
        proto_country: dict = {}
        proto_totals:  dict = {}
        country_totals: dict = {}
        dc_totals:     dict = {}
        for item in cls._cache:
            p  = item["protocol"]
            c  = item["country"]
            dc = item.get("dc", "?")
            proto_country[(p, c)] = proto_country.get((p, c), 0) + 1
            proto_totals[p]       = proto_totals.get(p, 0) + 1
            country_totals[c]     = country_totals.get(c, 0) + 1
            dc_totals[dc]         = dc_totals.get(dc, 0) + 1
        cls._proto_country_index = proto_country
        cls._proto_totals        = proto_totals
        cls._country_totals      = country_totals
        cls._dc_totals           = dc_totals

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        if cls._lock is None: cls._lock = asyncio.Lock()
        return cls._lock

    @classmethod
    async def reload(cls, bot=None) -> int:
        cls.is_loading = True
        prev_cnt = len(cls._cache)
        async with cls._get_lock():
            # محافظت در برابر Race Condition: اگر یک reload دیگر همین الان
            # (کمتر از ۱۰ ثانیه پیش) کارش تمام شده، این یکی صرفاً از آن نتیجه استفاده می‌کند
            # به‌جای تکرار فرآیند سنگین fetch از صدها منبع.
            now_mono = time.monotonic()
            if cls._cache and (now_mono - cls._last_reload_mono) < 10:
                cls.is_loading = False
                return len(cls._cache)

            logger.info("🔄 reload کش...")
            fail_count = 0
            try:
                await DatabaseManager.reenable_cooled_sources()
                sources     = await DatabaseManager.get_all_sources()
                active_urls = [r[1] for r in sources if r[2] == 1]
                logger.info(f"📡 {len(active_urls)} منبع فعال...")

                new_cache: list = []
                new_fps:   set  = set()
                connector = aiohttp.TCPConnector(limit=Config.MAX_CONCURRENT_FETCHES)
                async with aiohttp.ClientSession(connector=connector) as session:
                    results = await asyncio.gather(
                        *[SourceManager.process_source(session, u) for u in active_urls],
                        return_exceptions=True)

                for result in results:
                    if isinstance(result, BaseException): fail_count += 1; continue
                    items, failed = result
                    if failed: fail_count += 1
                    for item in items:
                        if item["fp"] not in new_fps:
                            new_fps.add(item["fp"])
                            new_cache.append(item)

                # Memory Optimizer — اگر از سقف گذشت، برش بزن
                if len(new_cache) > Config.MAX_CACHE_SIZE:
                    new_cache = new_cache[:Config.MAX_CACHE_SIZE]

                if new_cache:
                    delta = len(new_cache) - prev_cnt
                    cls._prev_delta  = f"{'+'if delta>=0 else ''}{delta:,} کانفیگ"
                    cls._cache       = new_cache
                    cls._global_fps  = new_fps
                    cls._last_update = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%H:%M:%S")
                    cls._rebuild_stats_index()
                    logger.info(f"✅ کش آماده — {len(cls._cache):,} کانفیگ (delta: {cls._prev_delta})")
                else:
                    logger.warning("⚠️  هیچ کانفیگی یافت نشد.")

                await DatabaseManager.add_log("INFO", f"Reload: {len(new_cache):,} configs, {fail_count} source failures")
                cls._last_reload_mono = now_mono

            except Exception as exc:
                logger.error(f"❌ خطای reload: {exc}", exc_info=True)
                await DatabaseManager.add_log("ERROR", str(exc), "CacheManager.reload")
            finally:
                cls.is_loading = False

        # Anomaly check بعد از unlock — فقط وقتی bot واقعی در دسترس باشد
        # (در post_init اولین reload بدون bot صدا زده می‌شود، پس چک را نادیده می‌گیریم)
        if bot is not None:
            try:
                asyncio.create_task(AnomalyDetector.check(bot, len(cls._cache), fail_count))
            except Exception:
                pass

        return len(cls._cache)

    @classmethod
    def get_filtered(cls, proto: str, country: str, limit: "int|None" = None) -> list:
        """
        رفع باگ «بارگذاری تمام کانفیگ‌ها در حافظه»: قبلاً این تابع همیشه کل
        نتایج منطبق را به‌صورت یک لیست کامل در حافظه می‌ساخت (result = [...])
        و شافل می‌کرد، حتی وقتی فراخوان فقط چند کانفیگ لازم داشت. حالا اگر
        limit داده شود، از الگوریتم reservoir sampling استفاده می‌شود که با
        یک پاس روی کش، بدون نگه‌داشتن کل نتایج منطبق در حافظه، دقیقاً `limit`
        آیتم تصادفی انتخاب می‌کند. اگر limit داده نشود (برای سازگاری با
        فراخوان‌های قدیمی)، رفتار قبلی حفظ می‌شود.
        """
        proto_l   = proto.lower()   if proto   != "ALL" else None
        country_l = country.lower() if country != "ALL" else None

        def _matches(c: dict) -> bool:
            if proto_l   is not None and c["protocol"] != proto_l:   return False
            if country_l is not None and c["country"]  != country_l: return False
            return True

        if limit is None:
            result  = [c for c in cls._cache if _matches(c)]
            configs = [i["config"] for i in result]
            random.shuffle(configs)
            return configs

        # --- Reservoir sampling: یک پاس، حافظه ثابت به‌اندازه‌ی limit ---
        reservoir: list = []
        seen = 0
        for c in cls._cache:
            if not _matches(c):
                continue
            seen += 1
            if len(reservoir) < limit:
                reservoir.append(c["config"])
            else:
                j = random.randint(0, seen - 1)
                if j < limit:
                    reservoir[j] = c["config"]
        return reservoir

    @classmethod
    def count_filtered(cls, proto: str, country: str) -> int:
        """
        رفع باگ #3 (اسکن کامل کش در توابع آماری): به‌جای پیمایش تک‌به‌تک کل
        کش (که می‌تواند ۵۰٬۰۰۰ آیتم باشد)، از ایندکس آماده‌ی
        _proto_country_index/_proto_totals/_country_totals که در reload()
        ساخته شده استفاده می‌شود — این یک lookup تقریباً O(1) یا حداکثر
        O(تعداد پروتکل‌ها/کشورهای متمایز) است، نه O(کل کش).
        """
        proto_l   = proto.lower()   if proto   != "ALL" else None
        country_l = country.lower() if country != "ALL" else None
        if proto_l is None and country_l is None:
            return len(cls._cache)
        if proto_l is not None and country_l is not None:
            return cls._proto_country_index.get((proto_l, country_l), 0)
        if proto_l is not None:
            return cls._proto_totals.get(proto_l, 0)
        return cls._country_totals.get(country_l, 0)

    @classmethod
    def search_configs(cls, query: str, limit: "int|None" = None) -> list:
        """
        جستجو در کانفیگ‌های کش. رفع باگ «جستجوی چندکلمه‌ای هرگز نتیجه‌ای
        برنمی‌گرداند»: قبلاً کل عبارت جستجو (مثلاً دقیقاً همان مثال راهنمای
        بات: "germany vless") به‌عنوان یک substring واحد چک می‌شد — و چون
        هیچ کانفیگی واقعاً رشته‌ی «germany vless» را کلمه‌به‌کلمه ندارد،
        چنین جستجویی همیشه صفر نتیجه می‌داد، دقیقاً برخلاف راهنمای خودِ بات.
        حالا هر جستجو به کلمات جدا (whitespace) شکسته می‌شود و یک کانفیگ
        فقط وقتی match می‌شود که همه‌ی کلمات (AND) هرکدام در حداقل یکی از
        فیلدهای config/پروتکل/کد کشور/نام کشور دیده شوند — حالا «germany
        vless» هر کانفیگ VLESS آلمانی را پیدا می‌کند، نه هیچ‌کدام را.
        رفع باگ «بازگشت تعداد بیشتر از درخواست»: اگر limit داده شود، به‌جای
        جمع‌آوری کل نتایج و برش بعدی با random.sample، از reservoir sampling
        با حافظه ثابت استفاده می‌شود.
        """
        terms = query.strip().lower().split()
        if not terms: return []

        def _matches(item: dict) -> bool:
            cfg_lower  = item["config"].lower()
            protocol   = item.get("protocol", "").lower()
            country    = item.get("country", "").lower()
            _flag, name_fa, name_en = COUNTRY_MAP.get(item.get("country",""), _UNKNOWN_COUNTRY)
            # رفع محدودیت «جستجو فقط فارسی» — حالا نام انگلیسی کشور هم در
            # جستجو لحاظ می‌شود، مثلاً کاربر می‌تواند "germany" یا "آلمان"
            # هر دو را جستجو کند.
            blob = f"{cfg_lower} {protocol} {country} {name_fa.lower()} {name_en.lower()}"
            return all(term in blob for term in terms)

        if limit is None:
            results = [item["config"] for item in cls._cache if _matches(item)]
            random.shuffle(results)
            return results

        reservoir: list = []
        seen = 0
        for item in cls._cache:
            if not _matches(item):
                continue
            seen += 1
            if len(reservoir) < limit:
                reservoir.append(item["config"])
            else:
                j = random.randint(0, seen - 1)
                if j < limit:
                    reservoir[j] = item["config"]
        return reservoir

    @classmethod
    def count_search(cls, query: str) -> int:
        """فقط تعداد نتایج جستجو را می‌شمارد — بدون ساخت لیست کامل در حافظه."""
        terms = query.strip().lower().split()
        if not terms: return 0
        n = 0
        for item in cls._cache:
            cfg_lower  = item["config"].lower()
            protocol   = item.get("protocol", "").lower()
            country    = item.get("country", "").lower()
            _flag, name_fa, name_en = COUNTRY_MAP.get(item.get("country",""), _UNKNOWN_COUNTRY)
            blob = f"{cfg_lower} {protocol} {country} {name_fa.lower()} {name_en.lower()}"
            if all(term in blob for term in terms):
                n += 1
        return n

    @classmethod
    def search_configs_with_count(cls, query: str, limit: "int|None" = None) -> "tuple[list,int]":
        """
        رفع باگ #3 (اسکن دوگانه‌ی کش): قبلاً هر جستجوی کاربر باعث دو پیمایش
        کامل و مستقل کش می‌شد — یک‌بار در count_search (فقط برای شمارش) و
        یک‌بار در search_configs (برای گرفتن نتایج). این تابع هر دو کار را
        در یک پاس انجام می‌دهد: هم reservoir sampling برای نتایج نمایشی و هم
        شمارش کل match‌ها هم‌زمان محاسبه می‌شوند — نصف زمان پردازش قبلی.
        """
        terms = query.strip().lower().split()
        if not terms: return [], 0

        def _matches(item: dict) -> bool:
            cfg_lower  = item["config"].lower()
            protocol   = item.get("protocol", "").lower()
            country    = item.get("country", "").lower()
            _flag, name_fa, name_en = COUNTRY_MAP.get(item.get("country",""), _UNKNOWN_COUNTRY)
            blob = f"{cfg_lower} {protocol} {country} {name_fa.lower()} {name_en.lower()}"
            return all(term in blob for term in terms)

        total = 0
        if limit is None:
            results = []
            for item in cls._cache:
                if _matches(item):
                    total += 1
                    results.append(item["config"])
            random.shuffle(results)
            return results, total

        reservoir: list = []
        for item in cls._cache:
            if not _matches(item):
                continue
            total += 1
            if len(reservoir) < limit:
                reservoir.append(item["config"])
            else:
                j = random.randint(0, total - 1)
                if j < limit:
                    reservoir[j] = item["config"]
        return reservoir, total


    @classmethod
    def get_channel_configs(cls) -> list:
        proto     = Config.CHANNEL_FILTER_PROTOCOL.lower()
        countries = Config.CHANNEL_FILTER_COUNTRIES
        return [
            i["config"] for i in cls._cache
            if (proto == "all" or i["protocol"] == proto)
            and (not countries or i["country"] in countries)
        ]

    @classmethod
    def stats(cls) -> dict:
        """
        رفع باگ #3: قبلاً این تابع با هر فراخوانی (هر بار که ادمین دکمه‌ی
        «آمار سیستم» یا «Cache Info» را می‌زد) کل کش را دوباره می‌پیمود.
        حالا مقادیر از _proto_totals/_country_totals/_dc_totals که در پایان
        هر reload() یک‌بار محاسبه شده‌اند خوانده می‌شوند — هیچ پیمایشی روی
        کل کش در زمان نمایش پنل انجام نمی‌شود.
        """
        return {
            "total":       len(cls._cache),
            "last_update": cls._last_update,
            "delta":       cls._prev_delta,
            "protocols":   dict(cls._proto_totals),
            "countries":   dict(cls._country_totals),
            "datacenters": dict(cls._dc_totals),
        }

# ═══════════════════════════════════════════════════════════════════════════════
# GitHubSourceFinder — جستجوی خودکار منابع جدید در GitHub
# ═══════════════════════════════════════════════════════════════════════════════
class GitHubSourceFinder:
    _QUERIES = [
        "v2ray vless config subscription",
        "vless vmess trojan free subscription",
        "free vpn config vless reality",
    ]
    _RAW_PATTERNS = [
        r"https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/[^\s\"'<>]+\.txt",
        r"https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/[^\s\"'<>]+sub",
    ]

    @classmethod
    async def search(cls, bot=None) -> int:
        headers = {"Accept": "application/vnd.github.v3+json"}
        if Config.GITHUB_TOKEN:
            headers["Authorization"] = f"token {Config.GITHUB_TOKEN}"
        timeout = aiohttp.ClientTimeout(total=15)
        found   = 0
        try:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                for q in cls._QUERIES:
                    url = f"https://api.github.com/search/repositories?q={aiohttp.helpers.quote(q)}&sort=stars&order=desc&per_page=10"
                    async with session.get(url) as resp:
                        if resp.status != 200: continue
                        data = await resp.json()
                    for item in data.get("items",[]):
                        html_url = item.get("html_url","")
                        repo     = item.get("full_name","")
                        stars    = item.get("stargazers_count",0)
                        # تبدیل به raw URL ممکن — فقط repo URL ذخیره می‌شود
                        saved = await DatabaseManager.save_github_source(
                            html_url, repo, stars)
                        if saved: found += 1
                    await asyncio.sleep(1)

            # گزارش به ادمین
            if bot:
                unnotified = await DatabaseManager.get_unnotified_github_sources()
                if unnotified:
                    lines = [f"🔍 *منابع GitHub جدید یافت شد ({len(unnotified)}):*\n"]
                    for row in unnotified[:10]:
                        lines.append(f"⭐ `{row[3]}` — [{row[2]}]({row[1]})")
                    await SmartNotifier.notify(bot, "github_found", "\n".join(lines))
                    await DatabaseManager.mark_github_notified([r[0] for r in unnotified])

        except Exception as exc:
            logger.warning(f"GitHubSourceFinder: {exc}")
        return found


# ═══════════════════════════════════════════════════════════════════════════════
# Force-Join Middleware
# ═══════════════════════════════════════════════════════════════════════════════
async def check_channel_membership(bot, user_id: int) -> bool:
    if not Config.REQUIRED_CHANNEL: return True
    try:
        m = await bot.get_chat_member(chat_id=Config.REQUIRED_CHANNEL, user_id=user_id)
        return m.status in ("member","creator","administrator")
    except TelegramError:
        return False

def make_join_keyboard(lang: str = "fa") -> InlineKeyboardMarkup:
    ch   = Config.REQUIRED_CHANNEL
    link = f"https://t.me/{ch.lstrip('@')}"
    return InlineKeyboardMarkup([[InlineKeyboardButton(T("join_channel",lang), url=link)]])

# ═══════════════════════════════════════════════════════════════════════════════
# کمک‌کننده‌های گروه
# ═══════════════════════════════════════════════════════════════════════════════
def _is_group(update: Update) -> bool:
    return update.effective_chat is not None and \
           update.effective_chat.type in ("group","supergroup","channel")

def _bot_is_addressed(update: Update, bot_username: "str|None") -> bool:
    """
    رفع باگ حیاتی «هیچ دستور/دکمه‌ای در گروه کار نمی‌کند»: قبلاً این تابع
    فقط دو حالت را «خطاب به بات» می‌شناخت: ریپلای مستقیم به پیام بات، یا
    وجود متنِ کامل `@usernameبات` هرجایی در پیام. اما تلگرام دستورهای گروهی
    را معمولاً به‌صورت `/addsource@YourBot` می‌فرستد (نه با @mention جدا)،
    و اگر ادمین صرفاً `/addsource https://...` را بدون منشن بات در گروه
    بفرستد (که رایج‌ترین حالت استفاده‌ی واقعی است)، هیچ‌کدام از دو شرط بالا
    برقرار نمی‌شد. در نتیجه global_guard در group=-1 بلافاصله
    ApplicationHandlerStop می‌زد و پیام هرگز به CommandHandler نمی‌رسید —
    بات کاملاً بی‌پاسخ می‌ماند، دقیقاً همان گزارش «/addsource هیچ پاسخی
    نمی‌دهد». حالا هر پیامی که با یک دستور شروع شود (`/cmd` یا
    `/cmd@BotUsername`) هم «خطاب به بات» محسوب می‌شود — چون تلگرام خودش
    فقط دستورهایی را که واقعاً برای این بات هستند تحویل می‌دهد (دستورهای
    `/cmd@AnotherBot` اصلاً به این هندلر نمی‌رسند)، پس نیازی به بررسی
    دستی username نیست. کال‌بک‌های دکمه‌های شیشه‌ای (اینلاین) هم چون از
    طریق تعامل مستقیم با پیام‌های خودِ بات صادر می‌شوند، همیشه «خطاب به
    بات» محسوب می‌شوند.
    """
    msg = update.effective_message
    if update.callback_query is not None:
        return True
    if not msg: return False
    if msg.text and msg.text.startswith("/"): return True
    if (msg.reply_to_message and msg.reply_to_message.from_user and bot_username
            and msg.reply_to_message.from_user.username == bot_username): return True
    if bot_username and f"@{bot_username}" in (msg.text or msg.caption or ""): return True
    return False

def _rk(update: Update) -> dict:
    if _is_group(update) and update.effective_message:
        return {"reply_to_message_id": update.effective_message.message_id}
    return {}

# ═══════════════════════════════════════════════════════════════════════════════
# Abuse Processing — پردازش هوشمند Abuse
# ═══════════════════════════════════════════════════════════════════════════════
async def process_abuse(update: Update, context: ContextTypes.DEFAULT_TYPE, weight: int = 1) -> bool:
    """True = کاربر باید متوقف شود."""
    user = update.effective_user
    if not user or user.id == Config.ADMIN_ID: return False
    # رفع باگ «کانتر Abuse در حافظه بی‌استفاده»: قبلاً AbuseTracker.record()
    # اینجا صدا زده می‌شد و یک امتیاز in-memory برمی‌گرداند که هیچ‌گاه در
    # تصمیم‌گیری استفاده نمی‌شد (فقط new_score بر پایه‌ی دیتابیس تصمیم‌گیر
    # بود) — این کانتر صرفاً سردرگمی ایجاد می‌کرد و حذف شد. تصمیم‌گیری همیشه
    # بر اساس امتیاز پایدار در دیتابیس است (که برخلاف کانتر حافظه، بعد از
    # ری‌استارت بات هم از دست نمی‌رود).
    abuse = await DatabaseManager.get_abuse(user.id)
    new_score = abuse["score"] + weight

    mute_until = None
    warned     = False

    if new_score >= Config.ABUSE_BAN_THRESHOLD:
        await DatabaseManager.ban_user(user.id, "Auto-ban: abuse score")
        await SmartNotifier.notify(context.bot, f"autoban_{user.id}",
            f"🚫 *Auto-Ban*\nکاربر `{user.id}` به دلیل Abuse مسدود شد.")
        return True

    if new_score >= Config.ABUSE_MUTE_THRESHOLD and not await DatabaseManager.is_muted(user.id):
        mute_until = (datetime.now(timezone.utc) + timedelta(minutes=Config.ABUSE_MUTE_MINUTES)).isoformat(timespec="seconds")
        try:
            lang = (await DatabaseManager.get_user_prefs(user.id))["language"]
            await context.bot.send_message(user.id, T("muted", lang))
        except Exception: pass

    if new_score >= Config.ABUSE_WARN_THRESHOLD and abuse["warn_count"] == 0:
        warned = True
        try:
            lang = (await DatabaseManager.get_user_prefs(user.id))["language"]
            await context.bot.send_message(user.id, T("abuse_warned", lang))
        except Exception: pass

    await DatabaseManager.update_abuse(
        user.id, new_score,
        abuse["warn_count"] + (1 if warned else 0),
        mute_until or abuse["mute_until"])
    return False

# ═══════════════════════════════════════════════════════════════════════════════
# Decorators
# ═══════════════════════════════════════════════════════════════════════════════
def admin_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *a, **kw):
        if not update.effective_user or update.effective_user.id != Config.ADMIN_ID: return
        return await func(update, context, *a, **kw)
    return wrapper

def is_allowed(user_id: int, prefs: dict, reqs: int, cfgs: int) -> "tuple[bool,str]":
    """بررسی محدودیت روزانه — True = مجاز، str = پیام خطا."""
    if user_id == Config.ADMIN_ID: return True, ""
    is_vip = prefs.get("is_vip", False)
    max_r  = Config.VIP_MAX_DAILY_REQUESTS if is_vip else Config.MAX_DAILY_REQUESTS
    max_c  = Config.VIP_MAX_DAILY_CONFIGS  if is_vip else Config.MAX_DAILY_CONFIGS
    if reqs >= max_r: return False, f"⚠️ سقف درخواست روزانه ({max_r}) تمام شد."
    if cfgs >= max_c: return False, f"⚠️ سقف کانفیگ روزانه ({max_c}) تمام شد."
    return True, ""

# ═══════════════════════════════════════════════════════════════════════════════
# Global Guard
# ═══════════════════════════════════════════════════════════════════════════════
async def global_guard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user: return
    # ادمین همیشه معاف از گیت «خطاب به بات در گروه» است — یک ادمینی که در
    # گروه مدیریتی خودش دستور می‌زند نباید هرگز به‌خاطر این گیت بی‌پاسخ بماند.
    if user.id != Config.ADMIN_ID and _is_group(update):
        if not _bot_is_addressed(update, context.bot.username if context.bot else None):
            raise ApplicationHandlerStop
    if await DatabaseManager.is_banned(user.id): raise ApplicationHandlerStop
    if await DatabaseManager.is_muted(user.id):  raise ApplicationHandlerStop
    await DatabaseManager.touch_user(user.id, user.username,
                                     getattr(user,"first_name",None))
    # Abuse: هر پیام = weight 1
    if update.message:
        await process_abuse(update, context, weight=1)

# ═══════════════════════════════════════════════════════════════════════════════
# UI Keyboards
# ═══════════════════════════════════════════════════════════════════════════════
def make_main_keyboard(user_id: int, lang: str = "fa") -> InlineKeyboardMarkup:
    is_adm = (user_id == Config.ADMIN_ID)
    rows   = [
        [InlineKeyboardButton(T("get_configs",lang),    callback_data="get_configs"),
         InlineKeyboardButton(T("random_cfg",lang),     callback_data="random_cfg")],
        [InlineKeyboardButton(T("filter_proto",lang),   callback_data="menu_proto"),
         InlineKeyboardButton(T("filter_country",lang), callback_data="menu_country")],
        [InlineKeyboardButton(T("search_cfg",lang),     callback_data="search_configs"),
         InlineKeyboardButton(T("my_profile",lang),     callback_data="my_profile")],
    ]
    # طبق درخواست صریح ادمین، دکمه‌ی «کانفیگ‌های پینگ گرفته‌شده» (سیستم Real
    # Ping Tester) و دکمه‌ی «لینک ساب من» (پنل تحت وب کاربر) هر دو کاملاً
    # حذف شدند. تنها دسترسی وب باقی‌مانده، پنل ادمین تحت وب است که فقط برای
    # خودِ ادمین نمایش داده می‌شود (پایین‌تر).
    rows.append([InlineKeyboardButton(T("lang_toggle",lang), callback_data="toggle_lang")])
    if is_adm:
        rows.append([InlineKeyboardButton(T("admin_panel",lang), callback_data="admin_panel")])
        if webdash_configured():
            rows.append([InlineKeyboardButton(
                "🌐 پنل ادمین تحت وب" if lang=="fa" else "🌐 Web Admin Panel",
                url=admin_panel_url())])
    return InlineKeyboardMarkup(rows)


def make_back_keyboard(lang: str = "fa") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(T("back",lang), callback_data="main_menu")]])

def make_admin_keyboard(page: int = 1, lang: str = "fa") -> InlineKeyboardMarkup:
    """پنل ادمین شیشه‌ای — ۲ صفحه."""
    if page == 1:
        rows = [
            [InlineKeyboardButton("📊 آمار سیستم",         callback_data="adm_stats"),
             InlineKeyboardButton("🏥 Health",              callback_data="adm_health")],
            [InlineKeyboardButton("💾 Cache Info",          callback_data="adm_cache"),
             InlineKeyboardButton("🔄 Reload کش",           callback_data="adm_reload")],
            [InlineKeyboardButton("📡 منابع",               callback_data="adm_sources"),
             InlineKeyboardButton("📈 بهترین منابع",        callback_data="adm_top_sources")],
            [InlineKeyboardButton("🐌 منابع کند",           callback_data="adm_slow_sources"),
             InlineKeyboardButton("🔬 Benchmark",           callback_data="adm_benchmark")],
            [InlineKeyboardButton("👥 کاربران",             callback_data="adm_users"),
             InlineKeyboardButton("🏆 Top کاربران",         callback_data="adm_top_users")],
            [InlineKeyboardButton("📤 Broadcast",           callback_data="adm_broadcast_menu"),
             InlineKeyboardButton("🚫 Ban/Unban",           callback_data="adm_ban_menu")],
            [InlineKeyboardButton("⭐ VIP",                 callback_data="adm_vip_menu"),
             InlineKeyboardButton("🛡 IP Blacklist",        callback_data="adm_blacklist")],
            [InlineKeyboardButton("📋 Logs",                callback_data="adm_logs"),
             InlineKeyboardButton("❌ Errors",              callback_data="adm_errors")],
            [InlineKeyboardButton("⚙️ Rules",               callback_data="adm_rules"),
             InlineKeyboardButton("💬 Feedback",            callback_data="adm_feedback")],
            [InlineKeyboardButton("💾 Backup DB",           callback_data="adm_backup"),
             InlineKeyboardButton("📤 Export کانفیگ",       callback_data="adm_export")],
            [InlineKeyboardButton("▶ صفحه ۲ »",            callback_data="admin_panel_2"),
             InlineKeyboardButton("🔙 منوی اصلی",           callback_data="main_menu")],
        ]
    else:
        rows = [
            [InlineKeyboardButton("🖥 CPU",                callback_data="adm_cpu"),
             InlineKeyboardButton("🧠 Memory",             callback_data="adm_memory")],
            [InlineKeyboardButton("🌐 GitHub Sources",     callback_data="adm_github"),
             InlineKeyboardButton("📊 Version Compare",    callback_data="adm_version")],
            [InlineKeyboardButton("👤 User Info",          callback_data="adm_userinfo_prompt"),
             InlineKeyboardButton("🔍 Find User",          callback_data="adm_finduser_prompt")],
            [InlineKeyboardButton("🔍 Find Config",        callback_data="adm_findconfig_prompt"),
             InlineKeyboardButton("📊 Analytics",          callback_data="adm_analytics")],
            [InlineKeyboardButton("🗑 Cleanup",             callback_data="adm_cleanup"),
             InlineKeyboardButton("📦 Tasks",              callback_data="adm_tasks")],
            [InlineKeyboardButton("« صفحه ۱",              callback_data="admin_panel"),
             InlineKeyboardButton("🔙 منوی اصلی",          callback_data="main_menu")],
        ]
    return InlineKeyboardMarkup(rows)


def make_broadcast_menu(lang: str = "fa") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📢 همه کاربران",           callback_data="bc_all")],
        [InlineKeyboardButton("✅ فعالان (۷ روز)",        callback_data="bc_active")],
        [InlineKeyboardButton("😴 غیرفعالان (۳۰+ روز)",  callback_data="bc_inactive")],
        [InlineKeyboardButton("⭐ کاربران VIP",           callback_data="bc_vip")],
        [InlineKeyboardButton("📦 ارسال کانفیگ",          callback_data="bc_configs")],
        [InlineKeyboardButton(T("back",lang),             callback_data="admin_panel")],
    ])

def make_proto_keyboard(current: str, lang: str = "fa") -> InlineKeyboardMarkup:
    # طبق درخواست ادمین (فیلتر پروتکل قوی‌تر): پروتکل‌های تازه‌پشتیبانی‌شده
    # (SSR، SOCKS، NAIVE، SNELL، HYSTERIA نسخه‌ی ۱) هم به فهرست فیلتر اضافه
    # شدند — قبلاً این‌ها حتی اگر در کش وجود داشتند، هیچ دکمه‌ی فیلتری برای
    # انتخاب مجزای‌شان وجود نداشت.
    PROTOS = ["ALL","VLESS","VMESS","TROJAN","SS","SSR",
              "HYSTERIA2","HYSTERIA","WIREGUARD","TUIC","SOCKS","NAIVE","SNELL"]
    kb = []
    for i in range(0, len(PROTOS), 2):
        row = []
        for p in PROTOS[i:i+2]:
            mark = " ✅" if current == p else ""
            row.append(InlineKeyboardButton(f"{p}{mark}", callback_data=f"set_proto_{p}"))
        kb.append(row)
    kb.append([InlineKeyboardButton(T("back",lang), callback_data="main_menu")])
    return InlineKeyboardMarkup(kb)

def make_country_keyboard(current: str, lang: str = "fa", page: int = 1) -> InlineKeyboardMarkup:
    """
    رفع باگ «همیشه فارسی»: قبلاً نام «همه کشورها» و نام هر کشور همیشه فارسی
    بود، صرف‌نظر از lang. حالا واقعاً بر اساس زبان کاربر انتخاب می‌شود.
    رفع نیاز به صفحه‌بندی: با گسترش COUNTRY_MAP به ۵۵+ کشور (طبق درخواست
    «فیلتر کشور بسیار قوی‌تر»)، یک کیبورد تخت دیگر مناسب نیست — این‌جا به
    صفحات ۱۸تایی (۶ ردیف × ۳ ستون) شکسته می‌شود، دقیقاً همان الگوی
    صفحه‌بندی که در بخش‌های دیگر بات (مثل لیست منابع) استفاده شده است.
    """
    PER_PAGE = 18
    all_label = "🌍 همه کشورها" if lang == "fa" else "🌍 All Countries"
    all_m = " ✅" if current == "ALL" else ""
    kb    = [[InlineKeyboardButton(f"{all_label}{all_m}", callback_data="set_cty_ALL")]]

    codes = list(COUNTRY_MAP.keys())
    total_pages = max(1, math.ceil(len(codes) / PER_PAGE))
    page  = max(1, min(page, total_pages))
    page_codes = codes[(page-1)*PER_PAGE : page*PER_PAGE]

    for i in range(0, len(page_codes), 3):
        row = []
        for code in page_codes[i:i+3]:
            flag, name_fa, name_en = COUNTRY_MAP[code]
            name = name_fa if lang == "fa" else name_en
            mark = " ✅" if current == code else ""
            row.append(InlineKeyboardButton(f"{flag} {name}{mark}", callback_data=f"set_cty_{code}"))
        kb.append(row)

    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("« قبلی" if lang=="fa" else "« Prev", callback_data=f"ctypage_{page-1}"))
    if page < total_pages:
        nav.append(InlineKeyboardButton("بعدی »" if lang=="fa" else "Next »", callback_data=f"ctypage_{page+1}"))
    if nav:
        kb.append(nav)

    kb.append([InlineKeyboardButton(T("back",lang), callback_data="main_menu")])
    return InlineKeyboardMarkup(kb)

def make_feedback_keyboard(config_hash: str, lang: str = "fa") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(T("feedback_not_work",lang), callback_data=f"fb_not_work_{config_hash}")],
        [InlineKeyboardButton(T("feedback_slow",lang),     callback_data=f"fb_slow_{config_hash}")],
        [InlineKeyboardButton(T("feedback_weak",lang),     callback_data=f"fb_weak_{config_hash}")],
        [InlineKeyboardButton(T("cancel",lang),            callback_data="main_menu")],
    ])

# ═══════════════════════════════════════════════════════════════════════════════
# send_main_menu
# ═══════════════════════════════════════════════════════════════════════════════
async def send_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE,
                          edit: bool = False) -> None:
    user_id = update.effective_user.id
    prefs   = await DatabaseManager.get_user_prefs(user_id)
    lang    = prefs["language"]
    rk      = _rk(update)

    if CacheManager.is_loading and not CacheManager._cache:
        text = T("loading", lang)
        if edit and update.callback_query:
            try: await update.callback_query.edit_message_text(text); return
            except BadRequest: pass
        await context.bot.send_message(update.effective_chat.id, text, **rk)
        return

    reqs, cfgs = await DatabaseManager.check_rate_limit(user_id)
    is_adm     = (user_id == Config.ADMIN_ID)
    is_vip     = prefs.get("is_vip", False)
    vip_badge  = f" {T('vip_badge',lang)}" if is_vip else ""
    cdisplay   = country_display(prefs["country"], lang)
    divider    = "━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # رفع باگ حیاتی «منوی اصلی همیشه فارسی است»: این پرکاربردترین صفحه‌ی
    # کل بات است (هر کاربر هر بار /start می‌زند این را می‌بیند) و قبلاً
    # کاملاً هاردکد فارسی بود — پارامتر lang هرگز واقعاً در متن این پیام
    # اعمال نمی‌شد. حالا هر دو زبان به‌طور کامل و درست پیاده‌سازی شده‌اند.
    if lang == "en":
        if is_adm:
            text = (
                f"{divider}\n"
                f"{T('welcome',lang)}\n"
                f"{divider}\n"
                f"🕐 Last updated: `{CacheManager._last_update}`\n"
                f"📦 Active configs: `{len(CacheManager._cache):,}`\n"
                f"🔄 Last change: `{CacheManager._prev_delta or '---'}`\n"
                f"{divider}\n"
                f"⚙️ Protocol: `{prefs['protocol']}`  |  🌍 Country: `{cdisplay}`\n"
                f"👑 *Admin — unlimited access*\n"
            )
        else:
            max_r = Config.VIP_MAX_DAILY_REQUESTS if is_vip else Config.MAX_DAILY_REQUESTS
            max_c = Config.VIP_MAX_DAILY_CONFIGS  if is_vip else Config.MAX_DAILY_CONFIGS
            rem_c = max(0, max_c - cfgs)
            text = (
                f"{divider}\n"
                f"{T('welcome',lang)}{vip_badge}\n"
                f"{divider}\n"
                f"🕐 Updated: `{CacheManager._last_update}`\n"
                f"📦 Configs available: `{len(CacheManager._cache):,}`\n"
                f"{divider}\n"
                f"⚙️ Protocol: `{prefs['protocol']}`  |  🌍 `{cdisplay}`\n"
                f"{divider}\n"
                f"📈 Today's usage:\n"
                f"  🔢 Requests: `{reqs}/{max_r}`\n"
                f"  📥 Configs:  `{cfgs}/{max_c}` — remaining: `{rem_c}`\n"
            )
    elif is_adm:
        text = (
            f"{divider}\n"
            f"{T('welcome',lang)}\n"
            f"{divider}\n"
            f"🕐 آخرین بروزرسانی: `{CacheManager._last_update}`\n"
            f"📦 کانفیگ‌های فعال: `{len(CacheManager._cache):,}`\n"
            f"🔄 تغییر آخر: `{CacheManager._prev_delta or '---'}`\n"
            f"{divider}\n"
            f"⚙️ پروتکل: `{prefs['protocol']}`  |  🌍 کشور: `{cdisplay}`\n"
            f"👑 *ادمین — بدون محدودیت*\n"
        )
    else:
        max_r    = Config.VIP_MAX_DAILY_REQUESTS if is_vip else Config.MAX_DAILY_REQUESTS
        max_c    = Config.VIP_MAX_DAILY_CONFIGS  if is_vip else Config.MAX_DAILY_CONFIGS
        rem_c    = max(0, max_c - cfgs)
        text = (
            f"{divider}\n"
            f"{T('welcome',lang)}{vip_badge}\n"
            f"{divider}\n"
            f"🕐 بروزرسانی: `{CacheManager._last_update}`\n"
            f"📦 کانفیگ‌های موجود: `{len(CacheManager._cache):,}`\n"
            f"{divider}\n"
            f"⚙️ پروتکل: `{prefs['protocol']}`  |  🌍 `{cdisplay}`\n"
            f"{divider}\n"
            f"📈 مصرف امروز:\n"
            f"  🔢 درخواست: `{reqs}/{max_r}`\n"
            f"  📥 کانفیگ:  `{cfgs}/{max_c}` — باقی: `{rem_c}`\n"
        )

    kb = make_main_keyboard(user_id, lang)
    if edit and update.callback_query:
        try:
            await update.callback_query.edit_message_text(text, reply_markup=kb, parse_mode="Markdown")
            return
        except BadRequest: pass
    await context.bot.send_message(update.effective_chat.id, text,
                                   reply_markup=kb, parse_mode="Markdown", **rk)


# ═══════════════════════════════════════════════════════════════════════════════
# دستورات کاربر
# ═══════════════════════════════════════════════════════════════════════════════
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await DatabaseManager.set_user_pref(update.effective_user.id, "user_state", None)
    await send_main_menu(update, context, edit=False)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    prefs  = await DatabaseManager.get_user_prefs(update.effective_user.id)
    lang   = prefs["language"]
    is_adm = update.effective_user.id == Config.ADMIN_ID
    # رفع باگ «/help همیشه فارسی است»: قبلاً lang از prefs خوانده می‌شد ولی
    # هرگز واقعاً برای انتخاب متن استفاده نمی‌شد — کاربرانی که زبان انگلیسی
    # را انتخاب کرده بودند هم همیشه همین متن فارسی هاردکدشده را می‌دیدند.
    if lang == "en":
        text = (
            "❓ *Bot Guide*\n\n"
            "📦 *Get Configs:* enter how many you want\n"
            "🎲 *Random:* one config with your current filters\n"
            "🔍 *Search:* a search term, e.g. `germany vless`\n"
            "🔧 *Protocol Filter:* config type\n"
            "🌍 *Country Filter:* destination country\n"
            "👤 *Profile:* your personal stats\n"
            "🌐 *Language:* switch between Persian/English\n\n"
            "📌 /start — main menu\n"
            "📌 /profile — your profile\n"
            "📌 /lang — change language\n"
        )
        if is_adm:
            text += (
                "\n━━━━━━━━━━━━━━━━━━\n"
                "👑 *Admin commands:*\n"
                "/admin — admin panel\n"
                "/stats — full stats\n"
                "/health — system health\n"
                "/reload — reload cache\n"
                "/benchmark — run benchmark\n"
                "/vip add/remove ID — manage VIP\n"
                "/ban ID — ban user\n"
                "/unban ID — unban user\n"
                "/broadcast MSG — broadcast message\n"
                "/addsource URL — add source\n"
                "/removesource ID — remove source\n"
                "/backup — DB backup\n"
                "/export — export all configs\n"
            )
    else:
        text = (
            "❓ *راهنمای ربات*\n\n"
            "📦 *دریافت کانفیگ:* عدد دلخواه را وارد کنید\n"
            "🎲 *تصادفی:* یک کانفیگ با فیلتر فعلی\n"
            "🔍 *جستجو:* عبارت مورد نظر مثل `germany vless`\n"
            "🔧 *فیلتر پروتکل:* نوع کانفیگ\n"
            "🌍 *فیلتر کشور:* کشور مقصد\n"
            "👤 *پروفایل:* آمار شخصی شما\n"
            "🌐 *زبان:* تغییر بین فارسی/انگلیسی\n\n"
            "📌 /start — منوی اصلی\n"
            "📌 /profile — پروفایل شما\n"
            "📌 /lang — تغییر زبان\n"
        )
        if is_adm:
            text += (
                "\n━━━━━━━━━━━━━━━━━━\n"
                "👑 *دستورات ادمین:*\n"
                "/admin — پنل ادمین\n"
                "/stats — آمار کامل\n"
                "/health — وضعیت سیستم\n"
                "/reload — بروزرسانی کش\n"
                "/benchmark — بنچمارک\n"
                "/vip add/remove ID — مدیریت VIP\n"
                "/ban ID — مسدودسازی\n"
                "/unban ID — رفع مسدودیت\n"
                "/broadcast MSG — پیام همگانی\n"
                "/addsource URL — افزودن منبع\n"
                "/removesource ID — حذف منبع\n"
                "/backup — پشتیبان DB\n"
                "/export — خروجی همه کانفیگ‌ها\n"
            )
    await update.message.reply_text(text, parse_mode="Markdown", **_rk(update))

async def lang_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    prefs   = await DatabaseManager.get_user_prefs(update.effective_user.id)
    new_lng = "en" if prefs["language"] == "fa" else "fa"
    await DatabaseManager.set_user_pref(update.effective_user.id, "language", new_lng)
    label   = "🇮🇷 زبان به فارسی تغییر یافت." if new_lng == "fa" else "🇬🇧 Language changed to English."
    await update.message.reply_text(label, **_rk(update))

async def profile_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid   = update.effective_user.id
    prefs = await DatabaseManager.get_user_prefs(uid)
    lang  = prefs["language"]
    full  = await DatabaseManager.get_user_full(uid)
    reqs, cfgs = await DatabaseManager.check_rate_limit(uid)
    # رفع باگ «/profile همیشه فارسی است»: مشابه /help، قبلاً lang خوانده
    # می‌شد ولی هرگز در انتخاب متن استفاده نمی‌شد.
    if lang == "en":
        text = (
            "👤 *Your Profile*\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"🆔 ID: `{uid}`\n"
            f"📛 Name: `{full.get('first_name','—')}`\n"
            f"🔗 Username: `{'@'+full['username'] if full.get('username') else '—'}`\n"
            f"⭐ VIP: `{'Yes' if prefs['is_vip'] else 'No'}`\n"
            f"🌍 Language: `{lang.upper()}`\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📦 Total downloaded: `{prefs['total_downloads']:,}` configs\n"
            f"⚙️ Current protocol: `{prefs['protocol']}`\n"
            f"🌍 Current country: `{country_display(prefs['country'], lang)}`\n"
            f"📅 First seen: `{(full.get('first_seen') or '—')[:10]}`\n"
            f"🕐 Last active: `{(full.get('last_seen') or '—')[:16].replace('T',' ')}`\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📈 Today: requests `{reqs}` | configs `{cfgs}`\n"
        )
    else:
        text = (
            "👤 *پروفایل شما*\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"🆔 آیدی: `{uid}`\n"
            f"📛 نام: `{full.get('first_name','—')}`\n"
            f"🔗 یوزرنیم: `{'@'+full['username'] if full.get('username') else '—'}`\n"
            f"⭐ VIP: `{'بله' if prefs['is_vip'] else 'خیر'}`\n"
            f"🌍 زبان: `{lang.upper()}`\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📦 کل دانلود: `{prefs['total_downloads']:,}` کانفیگ\n"
            f"⚙️ پروتکل فعلی: `{prefs['protocol']}`\n"
            f"🌍 کشور فعلی: `{country_display(prefs['country'], lang)}`\n"
            f"📅 اولین ورود: `{(full.get('first_seen') or '—')[:10]}`\n"
            f"🕐 آخرین فعالیت: `{(full.get('last_seen') or '—')[:16].replace('T',' ')}`\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📈 امروز: درخواست `{reqs}` | کانفیگ `{cfgs}`\n"
        )
    await update.message.reply_text(text, parse_mode="Markdown", **_rk(update))

# ═══════════════════════════════════════════════════════════════════════════════
# هندلر پیام متنی — دریافت تعداد / جستجو
# ═══════════════════════════════════════════════════════════════════════════════
async def user_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    prefs   = await DatabaseManager.get_user_prefs(user_id)
    lang    = prefs["language"]
    state   = prefs.get("user_state") or ""
    rk      = _rk(update)
    text_in = (update.message.text or "").strip()

    # ── حالت‌های ادمین: پرامپت‌های User Info / Find User / Find Config /
    #    افزودن و حذف دستی کانفیگ تست‌شده ───────────────────────────────────
    if state.startswith("adm_waiting_") and user_id == Config.ADMIN_ID:
        await DatabaseManager.set_user_pref(user_id, "user_state", None)
        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="admin_panel_2")]])

        if state == "adm_waiting_userinfo":
            target = None
            if text_in.lstrip("-").isdigit():
                target = await DatabaseManager.get_user_full(int(text_in))
            if not target:
                matches = await DatabaseManager.find_user(text_in.lstrip("@"))
                if matches:
                    target = await DatabaseManager.get_user_full(matches[0][0])
            if not target:
                await update.message.reply_text("❌ کاربری یافت نشد.", reply_markup=back_kb, **rk)
                return
            txt = (
                f"👤 *اطلاعات کاربر*\n"
                f"🆔 `{target['user_id']}`\n"
                f"📛 `{target.get('first_name') or '—'}`\n"
                f"🔗 `{('@'+target['username']) if target.get('username') else '—'}`\n"
                f"⭐ VIP: `{'بله' if target.get('is_vip') else 'خیر'}`\n"
                f"📦 دانلود کل: `{target.get('total_downloads',0):,}`\n"
                f"📅 اولین ورود: `{(target.get('first_seen') or '—')[:10]}`\n"
                f"🕐 آخرین فعالیت: `{(target.get('last_seen') or '—')[:16].replace('T',' ')}`\n"
            )
            await update.message.reply_text(txt, parse_mode="Markdown", reply_markup=back_kb, **rk)
            return

        if state == "adm_waiting_finduser":
            matches = await DatabaseManager.find_user(text_in)
            if not matches:
                await update.message.reply_text("❌ کاربری یافت نشد.", reply_markup=back_kb, **rk)
                return
            lines = [f"🆔 `{r[0]}` | {('@'+r[1]) if r[1] else (r[2] or '—')}" for r in matches[:20]]
            await update.message.reply_text(
                f"🔍 *{len(matches)} کاربر یافت شد:*\n\n" + "\n".join(lines),
                parse_mode="Markdown", reply_markup=back_kb, **rk)
            return

        if state == "adm_waiting_findconfig":
            results, total = CacheManager.search_configs_with_count(text_in, limit=10)
            if not results:
                await update.message.reply_text("❌ کانفیگی یافت نشد.", reply_markup=back_kb, **rk)
                return
            body = "\n\n".join(f"`{c}`" for c in results)
            await update.message.reply_text(
                f"🔍 *{total} کانفیگ یافت شد (تا ۱۰ مورد نمایش):*\n\n{body}",
                parse_mode="Markdown", reply_markup=back_kb, **rk)
            return

        # طبق درخواست ادمین، حالت‌های adm_waiting_addtested و adm_waiting_deltested
        # حذف شدند — سیستم Real Ping Tester (که این دو دستور برای مدیریت دستی
        # جدول تست‌شده‌ها استفاده می‌شدند) کاملاً از بات برداشته شده است.

        # طبق درخواست ادمین، حالت adm_waiting_archive_count حذف شد — سیستم
        # آرشیو کانفیگ‌های حذف‌شده کلاً برداشته شده است.

    # ── حالت جستجو: ورود کلمه کلیدی ────────────────────────────────────────
    if state == "waiting_search":
        if not text_in:
            await update.message.reply_text(T("search_empty", lang), **rk)
            return
        # رفع باگ «بارگذاری تمام کانفیگ‌ها در حافظه» + رفع باگ #3 (اسکن دوگانه):
        # قبلاً هم count_search (برای شمارش) و هم search_configs (برای گرفتن
        # نتایج) هرکدام یک پیمایش کامل مستقل روی کش انجام می‌دادند — یعنی هر
        # جستجوی کاربر دو برابر کار لازم را انجام می‌داد. حالا یک پاس واحد
        # هم total دقیق و هم یک نمونه‌ی تصادفی به‌اندازه‌ی سقف واقعی درخواست
        # (MAX_CONFIGS_PER_REQUEST) را هم‌زمان برمی‌گرداند؛ فقط همین نمونه در
        # context.user_data ذخیره می‌شود، نه کل نتایج.
        results, total = CacheManager.search_configs_with_count(text_in, limit=Config.MAX_CONFIGS_PER_REQUEST)
        await DatabaseManager.set_user_pref(user_id, "user_state", f"search_count:{text_in[:80]}")
        if not total:
            await DatabaseManager.set_user_pref(user_id, "user_state", None)
            await update.message.reply_text(T("search_none", lang), **rk)
            return
        await DatabaseManager.update_search_time(user_id)
        context.user_data["search_results"] = results
        await update.message.reply_text(
            T("search_results", lang, count=f"{total:,}") + f"\n\n{T('enter_count',lang)}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(T("cancel",lang), callback_data="main_menu")]]),
            parse_mode="Markdown", **rk)
        return

    # ── حالت جستجو: ورود تعداد ─────────────────────────────────────────────
    if state and state.startswith("search_count:"):
        if not text_in.isdigit() or int(text_in) <= 0:
            await update.message.reply_text(T("invalid_number", lang), **rk)
            return
        results = context.user_data.get("search_results", [])
        if not results:
            await DatabaseManager.set_user_pref(user_id, "user_state", None)
            await update.message.reply_text(T("search_none", lang), **rk)
            return
        requested = min(int(text_in), Config.MAX_CONFIGS_PER_REQUEST, len(results))
        if user_id != Config.ADMIN_ID:
            _, cfgs_today = await DatabaseManager.check_rate_limit(user_id)
            remaining     = max(0, (Config.VIP_MAX_DAILY_CONFIGS if prefs["is_vip"] else Config.MAX_DAILY_CONFIGS) - cfgs_today)
            requested     = min(requested, remaining)
        selected = random.sample(results, requested)
        # رفع باگ #20 (باقی ماندن نتایج جستجو در حافظه): قبلاً results در
        # context.user_data["search_results"] تا پایان کل نشست کاربر (session)
        # باقی می‌ماند، حتی بعد از اینکه همین‌جا مصرف شده بود — با افزایش
        # تعداد کاربرانی که هم‌زمان جستجو می‌کردند، این حافظه‌ی مصرف‌نشده جمع
        # می‌شد. حالا بلافاصله بعد از مصرف، صریحاً پاک می‌شود.
        context.user_data.pop("search_results", None)
        await DatabaseManager.set_user_pref(user_id, "user_state", None)
        await DatabaseManager.increment_usage(user_id, len(selected))
        await _deliver_configs(update, context, selected, lang, rk)
        return

    # ── حالت عادی: ورود تعداد کانفیگ ───────────────────────────────────────
    if state == "waiting_count":
        if not text_in.isdigit() or int(text_in) <= 0:
            await update.message.reply_text(T("invalid_number", lang), **rk)
            return
        requested = min(int(text_in), Config.MAX_CONFIGS_PER_REQUEST)
        if user_id != Config.ADMIN_ID:
            _, cfgs_today = await DatabaseManager.check_rate_limit(user_id)
            remaining     = max(0, (Config.VIP_MAX_DAILY_CONFIGS if prefs["is_vip"] else Config.MAX_DAILY_CONFIGS) - cfgs_today)
            if remaining <= 0:
                await DatabaseManager.set_user_pref(user_id, "user_state", None)
                await update.message.reply_text(T("daily_limit", lang), **rk)
                return
            requested = min(requested, remaining)
        # رفع باگ حیاتی: قبلاً این‌جا DatabaseManager.get_live_configs_for_delivery
        # صدا زده می‌شد که به استخر Real Ping Tester وابسته بود — اما آن
        # سیستم کاملاً حذف شده، پس این متد دیگر اصلاً وجود نداشت و هر درخواست
        # تحویل کانفیگ عادی («چند کانفیگ می‌خواهید؟») بلافاصله با AttributeError
        # کرش می‌کرد. حالا مستقیم از CacheManager (کش خام و همیشه در دسترس
        # منابع) استفاده می‌شود — دیگر مفهوم «تست‌شده در مقابل fallback خام»
        # وجود ندارد، چون تست پینگ کلاً از بات حذف شده است.
        matches = CacheManager.get_filtered(prefs["protocol"], prefs["country"], limit=requested)
        if not matches:
            await DatabaseManager.set_user_pref(user_id, "user_state", None)
            await update.message.reply_text(T("no_configs", lang), **rk)
            return
        final    = min(requested, len(matches))
        selected = random.sample(matches, final)
        await DatabaseManager.set_user_pref(user_id, "user_state", None)
        await DatabaseManager.increment_usage(user_id, len(selected))
        # اگر تعداد واقعی کمتر از درخواست کاربر بود (کش هنوز به آن اندازه پر
        # نشده)، صریح توضیح می‌دهیم — قبلاً این افت سایلنت بود و کاربر فکر
        # می‌کرد باگی رخ داده، نه اینکه فقط همین تعداد در کش موجود بود.
        shortfall = requested - final
        await _deliver_configs(update, context, selected, lang, rk, shortfall=shortfall)

# ── helper: تحویل کانفیگ ───────────────────────────────────────────────────
async def _deliver_configs(update: Update, context: ContextTypes.DEFAULT_TYPE,
                            selected: list, lang: str, rk: dict, shortfall: int = 0) -> None:
    # طبق حذف کامل سیستم Real Ping Tester، دیگر تمایزی بین «تست‌شده» و
    # «خام» وجود ندارد — همه‌ی کانفیگ‌ها مستقیماً از کش زنده‌ی منابع می‌آیند.
    warn = ""
    if shortfall > 0:
        warn += (
            f"ℹ️ فقط {len(selected)} کانفیگ موجود بود (کمتر از {len(selected)+shortfall} درخواستی).\n\n"
            if lang == "fa" else
            f"ℹ️ Only {len(selected)} configs were available (fewer than the {len(selected)+shortfall} requested).\n\n"
        )
    cfg_label = "کانفیگ" if lang == "fa" else "configs"
    if len(selected) < 10:
        body   = "\n\n".join(f"`{c}`" for c in selected)
        # رفع باگ «برخورد هش»: قبلاً فقط ۶۴ کاراکتر اول یک کانفیگ (selected[0])
        # هش می‌شد؛ چون بسیاری از URI های VLESS/VMess در همان ۶۴ کاراکتر اول
        # (پروتکل + ابتدای UUID) مشترک هستند، دو کانفیگ کاملاً متفاوت هش
        # یکسان می‌گرفتند و فیدبک کاربر به کانفیگ اشتباه نسبت داده می‌شد. حالا
        # کل محتوای همه‌ی کانفیگ‌های این بسته با هم هش می‌شود (نه فقط پیشوند
        # یک نمونه) تا شناسه واقعاً یکتای این بسته‌ی مشخص باشد. طول digest به
        # ۱۶ کاراکتر افزایش یافته (کماکان به‌راحتی داخل سقف ۶۴ بایت
        # callback_data تلگرام جا می‌شود).
        chash  = hashlib.sha256("\n".join(selected).encode()).hexdigest()[:16]
        header = f"{len(selected)} {cfg_label}" if lang == "en" else f"{len(selected)} کانفیگ"
        msg    = await update.message.reply_text(
            f"{warn}📦 *{header}:*\n\n{body}",
            parse_mode="Markdown",
            reply_markup=make_feedback_keyboard(chash, lang),
            **rk)
    else:
        # رفع باگ #9/#25 (عدم آزادسازی حافظه پس از ارسال فایل): قبلاً bio
        # پس از send_document به‌طور صریح بسته نمی‌شد و تا اجرای بعدی گاربیج
        # کالکشن در حافظه باقی می‌ماند. حالا با try/finally صریحاً close()
        # می‌شود تا بافر داخلی فوراً آزاد شود، نه با تأخیر و وابسته به GC.
        bio = io.BytesIO("\n".join(selected).encode())
        bio.seek(0)
        caption = (f"{warn}📦 `{len(selected):,}` {cfg_label}")
        try:
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=bio,
                filename=f"configs_{len(selected)}.txt",
                caption=caption,
                parse_mode="Markdown", **rk)
        finally:
            bio.close()
    await send_main_menu(update, context, edit=False)


# ═══════════════════════════════════════════════════════════════════════════════
# دستورات ادمین
# ═══════════════════════════════════════════════════════════════════════════════
@admin_only
async def admin_panel_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = "👑 *پنل مدیریت*\n\nیک بخش را انتخاب کنید:"
    await update.message.reply_text(text, reply_markup=make_admin_keyboard(1), parse_mode="Markdown")

@admin_only
async def admin_stats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(await _build_stats_text(), parse_mode="Markdown")

@admin_only
async def admin_health_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(await _build_health_text(), parse_mode="Markdown")

@admin_only
async def admin_reload_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg   = await update.message.reply_text("🔄 در حال بروزرسانی کش...")
    count = await CacheManager.reload(bot=context.bot)
    await msg.edit_text(f"✅ بروزرسانی کامل شد.\n📦 کانفیگ‌های فعال: `{count:,}`\n🔄 تغییر: `{CacheManager._prev_delta}`", parse_mode="Markdown")

@admin_only
async def admin_vip_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    args = context.args
    if not args or args[0] not in ("add","remove","list"):
        await update.message.reply_text("📝 استفاده:\n`/vip add ID`\n`/vip remove ID`\n`/vip list`", parse_mode="Markdown")
        return
    action = args[0]
    if action == "list":
        vips  = await DatabaseManager.get_vip_users()
        lines = [f"⭐ `{r[0]}` @{r[1] or '—'} {(r[3] or '')[:10]}" for r in vips]
        await update.message.reply_text(
            f"⭐ *VIP Users ({len(vips)}):*\n\n" + "\n".join(lines or ["(خالی)"]),
            parse_mode="Markdown")
        return
    if len(args) < 2:
        await update.message.reply_text("❌ آیدی را وارد کنید."); return
    try:   tid = int(args[1].lstrip("@"))
    except: await update.message.reply_text("❌ آیدی نامعتبر."); return
    await DatabaseManager.set_vip(tid, action == "add")
    await update.message.reply_text(f"{'✅ VIP اضافه' if action=='add' else '❎ VIP حذف'} شد: `{tid}`", parse_mode="Markdown")

@admin_only
async def admin_ban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not context.args[0].lstrip("-").isdigit():
        await update.message.reply_text("📝 `/ban ID [دلیل]`", parse_mode="Markdown"); return
    tid    = int(context.args[0])
    reason = " ".join(context.args[1:])
    if tid == Config.ADMIN_ID:
        await update.message.reply_text("❌ نمی‌توان ادمین را مسدود کرد."); return
    await DatabaseManager.ban_user(tid, reason)
    await update.message.reply_text(f"🚫 کاربر `{tid}` مسدود شد.", parse_mode="Markdown")

@admin_only
async def admin_unban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not context.args[0].lstrip("-").isdigit():
        await update.message.reply_text("📝 `/unban ID`", parse_mode="Markdown"); return
    ok = await DatabaseManager.unban_user(int(context.args[0]))
    await update.message.reply_text("✅ رفع مسدودیت شد." if ok else "❌ در لیست نبود.")

@admin_only
async def admin_broadcast_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text(
            "📝 استفاده:\n`/broadcast MSG` — همه\n"
            "`/broadcast active MSG` — فعالان ۷ روز\n"
            "`/broadcast configs N` — N کانفیگ به همه",
            parse_mode="Markdown"); return
    target = "all"
    args   = context.args[:]
    if args[0] in ("active","vip","inactive","configs"):
        target = args.pop(0)
    msg_text = " ".join(args)
    if target == "configs":
        n   = int(msg_text) if msg_text.isdigit() else 5
        await _broadcast_configs(update, context, n); return
    if target == "active":
        uids = [r[0] for r in await DatabaseManager.get_active_users(7)]
    elif target == "vip":
        uids = [r[0] for r in await DatabaseManager.get_vip_users()]
    elif target == "inactive":
        uids = [r[0] for r in await DatabaseManager.get_inactive_users(30)]
    else:
        uids = await DatabaseManager.get_all_user_ids()
    await _do_broadcast(update, context, uids, msg_text)

async def _do_broadcast(update, context, uids: list, msg_text: str) -> None:
    status = await update.message.reply_text(f"📤 ارسال به `{len(uids):,}` کاربر...", parse_mode="Markdown")
    sent = failed = 0
    for uid in uids:
        for attempt in range(2):
            try:
                await context.bot.send_message(uid, f"📢 *پیام ادمین:*\n\n{msg_text}", parse_mode="Markdown")
                sent += 1; break
            except TelegramError as exc:
                ra = getattr(exc, "retry_after", None)
                if ra and attempt == 0: await asyncio.sleep(float(ra)+0.5)
                else: failed += 1; break
        await asyncio.sleep(0.05)
    await status.edit_text(f"✅ ارسال کامل\n📨 موفق: `{sent:,}`\n❌ ناموفق: `{failed:,}`", parse_mode="Markdown")

async def _broadcast_configs(update, context, n: int) -> None:
    uids    = await DatabaseManager.get_all_user_ids()
    configs = CacheManager.get_filtered("ALL","ALL", limit=n)
    if not configs:
        await update.message.reply_text("❌ کانفیگی موجود نیست."); return
    payload = "📦 *کانفیگ‌های جدید:*\n\n" + "\n\n".join(f"`{c}`" for c in configs[:5])
    msg     = safe_truncate(payload, 4090)
    status  = await update.message.reply_text(f"📤 ارسال {n} کانفیگ به {len(uids):,} کاربر...")
    sent = failed = 0
    for uid in uids:
        try:
            await context.bot.send_message(uid, msg, parse_mode="Markdown")
            sent += 1
        except Exception:
            failed += 1
        await asyncio.sleep(0.07)
    await status.edit_text(f"✅ موفق: `{sent:,}` | ناموفق: `{failed:,}`", parse_mode="Markdown")

@admin_only
async def admin_addsource_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    رفع باگ «/addsource هیچ پاسخی نمی‌دهد»: علت واقعی این بود که
    global_guard (که روی group=-1 برای هر پیامی، حتی پیام‌های ادمین، اجرا
    می‌شد) در چت‌های گروهی هر پیامی را که دقیقاً @username بات را در متن
    نداشت «خطاب‌نشده به بات» تشخیص می‌داد و با ApplicationHandlerStop آن
    را متوقف می‌کرد — پیش از اینکه اصلاً به این handler برسد. این یعنی
    /addsource (و در واقع تقریباً هر دستور دیگری) در گروه‌ها همیشه ساکت
    شکست می‌خورد. آن گیت اصلاح شده (دستورهای اسلش و پیام‌های ادمین همیشه
    «خطاب‌شده» محسوب می‌شوند) — این handler خودش از ابتدا منطق درستی
    داشت. یک try/except عمومی هم اضافه شده تا حتی یک خطای غیرمنتظره هم
    هرگز باعث سکوت کامل بات برای ادمین نشود.
    """
    try:
        if not context.args:
            await update.message.reply_text(
                "📝 استفاده: `/addsource URL`\nمثال:\n`/addsource https://raw.githubusercontent.com/user/repo/main/list.txt`",
                parse_mode="Markdown")
            return
        url = context.args[0].strip()
        # رفع باگ SSRF: قبلاً فقط scheme/netloc چک می‌شد. حالا هاست resolve شده و
        # همه‌ی IP های بازگشتی در برابر بازه‌های خصوصی/loopback/link-local/متادیتا
        # (مثل 169.254.169.254) اعتبارسنجی می‌شوند — و resolve در ترد جداگانه
        # اجرا می‌شود تا event loop اصلی بات را بلاک نکند.
        safe, reason = await SSRFGuard.is_safe_url(url)
        if not safe:
            logger.warning(f"addsource: تلاش برای افزودن URL ناامن توسط ادمین رد شد — {url} — {reason}")
            await update.message.reply_text(f"❌ URL نامعتبر یا ناامن: {reason}")
            return
        ok, reason = await DatabaseManager.add_source(url)
        if ok:
            await update.message.reply_text(f"✅ منبع اضافه شد:\n`{url}`", parse_mode="Markdown")
        elif reason == "duplicate":
            await update.message.reply_text("❌ این URL قبلاً به لیست منابع اضافه شده است.")
        else:
            await update.message.reply_text(f"❌ خطا در افزودن منبع: {reason}")
    except Exception as exc:
        logger.error(f"admin_addsource_cmd: خطای غیرمنتظره: {exc}", exc_info=True)
        await update.message.reply_text(f"❌ خطای غیرمنتظره هنگام افزودن منبع: {type(exc).__name__}: {exc}")

@admin_only
async def admin_removesource_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("📝 `/removesource ID`", parse_mode="Markdown"); return
    ok = await DatabaseManager.remove_source(int(context.args[0]))
    await update.message.reply_text("✅ حذف شد." if ok else "❌ یافت نشد.")

@admin_only
async def admin_backup_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg  = await update.message.reply_text("💾 در حال تهیه پشتیبان...")
    data = await DatabaseManager.backup_db()
    bio  = io.BytesIO(data)
    bio.seek(0)
    ts   = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M")
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=bio,
            filename=f"backup_{ts}.db",
            caption=f"💾 پشتیبان دیتابیس — {ts}")
    finally:
        bio.close()
    await msg.delete()

@admin_only
async def admin_export_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    configs = CacheManager.get_filtered("ALL","ALL")
    if not configs:
        await update.message.reply_text("❌ کانفیگی موجود نیست."); return
    bio = io.BytesIO("\n".join(configs).encode())
    bio.seek(0)
    ts  = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M")
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=bio,
            filename=f"all_configs_{ts}.txt",
            caption=f"📤 Export — {len(configs):,} کانفیگ")
    finally:
        bio.close()

@admin_only
async def admin_benchmark_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg  = await update.message.reply_text("🔬 *Benchmark در حال اجرا...*", parse_mode="Markdown")
    m0   = _read_mem_mb()
    c0   = _read_cpu_percent()
    t0   = time.monotonic()
    prev = len(CacheManager._cache)
    cnt  = await CacheManager.reload(bot=context.bot)
    dt   = time.monotonic() - t0
    m1   = _read_mem_mb()
    text = (
        "🔬 *نتیجه Benchmark*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"⏱ مدت Reload:   `{dt:.2f}` ثانیه\n"
        f"📦 قبل:          `{prev:,}` کانفیگ\n"
        f"📦 بعد:          `{cnt:,}` کانفیگ\n"
        f"🔄 تغییر:        `{CacheManager._prev_delta}`\n"
        f"🧠 RAM قبل:      `{m0:.1f} MB`\n"
        f"🧠 RAM بعد:      `{m1:.1f} MB`\n"
        f"📊 CPU:          `{c0:.1f}%`\n"
        f"⚡ سرعت:         `{cnt/dt if dt>0 else 0:.0f}` cfg/s\n"
    )
    await msg.edit_text(text, parse_mode="Markdown")

# ═══════════════════════════════════════════════════════════════════════════════
# توابع build متن ادمین
# ═══════════════════════════════════════════════════════════════════════════════
async def _build_stats_text() -> str:
    s          = CacheManager.stats()
    srcs       = await DatabaseManager.get_all_sources()
    act_srcs   = sum(1 for r in srcs if r[2]==1)
    total_u    = await DatabaseManager.count_total_users()
    banned     = await DatabaseManager.get_banned_users()
    vips       = await DatabaseManager.get_vip_users()
    active_u   = await DatabaseManager.get_active_users(7)
    top_u      = await DatabaseManager.get_top_users(3)

    proto_lines = "\n".join(
        f"  • {k.upper()}: `{v:,}`"
        for k,v in sorted(s["protocols"].items(), key=lambda x:-x[1]))
    dc_lines = "\n".join(
        f"  • {k}: `{v:,}`"
        for k,v in sorted(s.get("datacenters",{}).items(), key=lambda x:-x[1])[:5])
    top_lines = "\n".join(
        f"  {i+1}. `{r[0]}` @{r[1] or '—'} — `{r[3]:,}`"
        for i,r in enumerate(top_u))

    return safe_truncate(
        "📊 *آمار جامع سیستم*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 کانفیگ: `{s['total']:,}` | 🔄 `{s['delta'] or '---'}`\n"
        f"🕐 آپدیت: `{s['last_update']}`\n"
        f"📡 منابع فعال: `{act_srcs}/{len(srcs)}`\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👥 کل کاربران: `{total_u:,}`\n"
        f"✅ فعال ۷ روز: `{len(active_u):,}` | ⭐ VIP: `{len(vips)}`\n"
        f"🚫 مسدود: `{len(banned)}`\n\n"
        f"🏆 *برتر دانلود:*\n{top_lines}\n\n"
        f"🔌 *پروتکل‌ها:*\n{proto_lines}\n\n"
        f"🏢 *دیتاسنترها (برتر):*\n{dc_lines}\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⏱ آپتایم: `{_format_uptime(time.time()-_START_TIME)}`\n"
        f"🧠 RAM: `{_read_mem_mb():.1f} MB`\n"
        f"💻 CPU: `{_read_cpu_percent():.1f}%`\n"
    )

async def _build_health_text() -> str:
    mem  = _read_mem_mb()
    cpu  = _read_cpu_percent()
    srcs = await DatabaseManager.get_all_sources()
    dead = sum(1 for r in srcs if r[2]==0)
    tasks_n = len(asyncio.all_tasks())
    qh      = DatabaseManager.get_write_queue_health()
    status  = "🟢 سالم" if cpu < 80 and mem < Config.MEM_OPTIMIZER_MB else "🟡 هشدار"
    if qh["dropped_total"] > 0:
        status = "🔴 بحرانی (دورریز صف DB)"
    return (
        f"🏥 *وضعیت سیستم — {status}*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🧠 RAM:        `{mem:.1f} MB`\n"
        f"💻 CPU:        `{cpu:.1f}%`\n"
        f"⏱ آپتایم:     `{_format_uptime(time.time()-_START_TIME)}`\n"
        f"🐍 Python:     `{platform.python_version()}`\n"
        f"🖥 OS:         `{platform.system()} {platform.release()}`\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 Cache:      `{len(CacheManager._cache):,}`\n"
        f"⚙️ Tasks:      `{tasks_n}`\n"
        f"📋 DB Queue:   `{qh['queue_size']}` (overflow: `{qh['overflow_size']}`, دورریز کل: `{qh['dropped_total']}`)\n"
        f"📡 Dead Srcs:  `{dead}`\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚠️ RAM Alert > `{Config.MEM_OPTIMIZER_MB}MB`\n"
        f"⚠️ CPU Alert > `{Config.CPU_ALERT_THRESHOLD:.0f}%`\n"
    )

async def _build_cache_text() -> str:
    s = CacheManager.stats()
    proto_txt = " | ".join(f"{k.upper()}:{v:,}" for k,v in sorted(s["protocols"].items(), key=lambda x:-x[1])[:6])
    cty_txt   = " | ".join(
        f"{COUNTRY_MAP.get(k,_UNKNOWN_COUNTRY)[0]}{k}:{v}"
        for k,v in sorted(s["countries"].items(), key=lambda x:-x[1])[:6])
    return (
        f"💾 *Cache Info*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"📦 کل: `{s['total']:,}`\n"
        f"🕐 آپدیت: `{s['last_update']}`\n"
        f"🔄 تغییر: `{s['delta'] or '---'}`\n"
        f"🔌 پروتکل:\n`{proto_txt}`\n\n"
        f"🌍 کشورها:\n`{cty_txt}`\n"
    )

async def _build_sources_text(page: int = 1) -> "tuple[str, int, int]":
    # PAGE کاهش یافت (10 → 5): چون حالا لینک کامل (نه بریده‌شده به 60 کاراکتر)
    # نمایش داده می‌شود، فضای بیشتری لازم است تا از سقف پیام تلگرام رد نشویم.
    PAGE   = 5
    srcs   = await DatabaseManager.get_all_sources()
    total  = max(1,(len(srcs)+PAGE-1)//PAGE)
    page   = max(1,min(page,total))
    chunk  = srcs[(page-1)*PAGE:page*PAGE]
    lines  = [f"📡 *منابع (صفحه {page}/{total}):*\n"]
    for r in chunk:
        st = "🟢" if r[2]==1 else "🔴"
        dc = r[5] or "?"
        # لینک کامل و بدون قیچی شدن نمایش داده می‌شود (قبلاً با [:60]... بریده می‌شد).
        lines.append(f"{st} `#{r[0]}` ❌`{r[3]}` 🏢`{dc}`\n`{r[1]}`\n")
    return safe_truncate("\n".join(lines), 4000), page, total


def make_sources_pagination_keyboard(page: int, total: int) -> InlineKeyboardMarkup:
    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("« قبلی", callback_data=f"adm_srcpage_{page-1}"))
    if page < total:
        nav.append(InlineKeyboardButton("بعدی »", callback_data=f"adm_srcpage_{page+1}"))
    rows = [nav] if nav else []
    rows.append([InlineKeyboardButton("🔙", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)

# ═══════════════════════════════════════════════════════════════════════════════
# Callback Router — مرکزی‌ترین هندلر
# ═══════════════════════════════════════════════════════════════════════════════
async def callback_router(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q or not update.effective_user: return
    await q.answer()

    uid   = update.effective_user.id
    data  = q.data or ""
    prefs = await DatabaseManager.get_user_prefs(uid)
    lang  = prefs["language"]

    # ── منوی اصلی ──────────────────────────────────────────────────────────
    if data == "main_menu":
        await DatabaseManager.set_user_pref(uid, "user_state", None)
        await send_main_menu(update, context, edit=True)

    # ── زبان ───────────────────────────────────────────────────────────────
    elif data == "toggle_lang":
        nl = "en" if lang=="fa" else "fa"
        await DatabaseManager.set_user_pref(uid, "language", nl)
        await send_main_menu(update, context, edit=True)

    # ── فیلتر پروتکل ───────────────────────────────────────────────────────
    elif data == "menu_proto":
        try:
            await q.edit_message_text(T("proto_select",lang),
                reply_markup=make_proto_keyboard(prefs["protocol"],lang),
                parse_mode="Markdown")
        except BadRequest: pass

    elif data.startswith("set_proto_"):
        new_p = data.removeprefix("set_proto_")
        await DatabaseManager.set_user_pref(uid,"protocol",new_p)
        prefs["protocol"] = new_p
        try:
            await q.edit_message_text(T("proto_select",lang),
                reply_markup=make_proto_keyboard(new_p,lang), parse_mode="Markdown")
        except BadRequest: pass

    # ── فیلتر کشور ─────────────────────────────────────────────────────────
    elif data == "menu_country":
        try:
            await q.edit_message_text(T("country_select",lang),
                reply_markup=make_country_keyboard(prefs["country"],lang), parse_mode="Markdown")
        except BadRequest: pass

    elif data.startswith("set_cty_"):
        new_c = data.removeprefix("set_cty_")
        await DatabaseManager.set_user_pref(uid,"country",new_c)
        prefs["country"] = new_c
        try:
            await q.edit_message_text(T("country_select",lang),
                reply_markup=make_country_keyboard(new_c,lang), parse_mode="Markdown")
        except BadRequest: pass

    elif data.startswith("ctypage_"):
        try:
            page = int(data.rsplit("_", 1)[1])
        except (ValueError, IndexError):
            page = 1
        try:
            await q.edit_message_text(T("country_select",lang),
                reply_markup=make_country_keyboard(prefs["country"],lang,page), parse_mode="Markdown")
        except BadRequest: pass

    # ── دریافت کانفیگ ──────────────────────────────────────────────────────
    elif data == "get_configs":
        if not await check_channel_membership(context.bot, uid):
            try: await q.edit_message_text(T("force_join_msg",lang), reply_markup=make_join_keyboard(lang), parse_mode="Markdown")
            except BadRequest: pass
            return
        reqs, cfgs = await DatabaseManager.check_rate_limit(uid)
        ok, err    = is_allowed(uid, prefs, reqs, cfgs)
        if not ok:
            try: await q.edit_message_text(err, reply_markup=make_back_keyboard(lang))
            except BadRequest: pass
            return
        total = CacheManager.count_filtered(prefs["protocol"], prefs["country"])
        if not total:
            try: await q.edit_message_text(T("no_configs",lang), reply_markup=make_back_keyboard(lang))
            except BadRequest: pass
            return
        await DatabaseManager.set_user_pref(uid, "user_state", "waiting_count")
        prompt_text = f"{T('enter_count',lang)}\n\n📊 موجودی: `{total:,}` کانفیگ"
        try:
            await q.edit_message_text(
                prompt_text,
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(T("cancel",lang), callback_data="main_menu")]]),
                parse_mode="Markdown")
        except BadRequest: pass
        # رفع باگ «در گروه، پاسخ متنی کاربر (عدد) هرگز به بات نمی‌رسد»:
        # ForceReply فقط روی پیام تازه‌ارسال‌شده کار می‌کند، نه روی ادیت یک
        # پیام قدیمی — پس در گروه، جدا از ادیت بالا، یک پیام کوچک با
        # ForceReplyً می‌فرستیم تا تلگرام خودش پاسخ بعدی کاربر را به‌عنوان
        # ریپلای به بات علامت بزند؛ این باعث می‌شود global_guard آن را
        # «خطاب به بات» تشخیص دهد، حتی اگر کاربر خودش دستی ریپلای نزند.
        if _is_group(update):
            try:
                await context.bot.send_message(
                    q.message.chat_id, T("enter_count", lang),
                    reply_to_message_id=q.message.message_id,
                    reply_markup=ForceReply(selective=True, input_field_placeholder="50"))
            except BadRequest:
                # رفع باگ #27 (عدم مدیریت پیام مرجع حذف‌شده در ForceReply):
                # قبلاً اگر پیام مرجع (q.message، همان پیامی که دکمه رویش
                # بود) قبل از این لحظه حذف شده بود، send_message با
                # reply_to_message_id نامعتبر شکست می‌خورد و این خطا بی‌صدا
                # catch می‌شد — ادمین هیچ اطلاعی نداشت که ForceReply اصلاً
                # ارسال نشده و باید دوباره تلاش کند؛ فقط منتظر پاسخی می‌ماند
                # که هرگز به بات نمی‌رسید. حالا اگر ارسال با reply ناموفق
                # شود، بدون reply_to_message_id دوباره تلاش می‌شود تا حداقل
                # ForceReply به دست ادمین برسد، و اگر آن هم شکست بخورد یک
                # پیام خطای صریح فرستاده می‌شود.
                try:
                    await context.bot.send_message(
                        q.message.chat_id, T("enter_count", lang),
                        reply_markup=ForceReply(selective=True, input_field_placeholder="50"))
                except Exception:
                    try:
                        await context.bot.send_message(
                            q.message.chat_id,
                            "⚠️ پیام مرجع پیدا نشد — لطفاً دوباره روی دکمه بزنید یا مستقیم عدد را بفرستید.")
                    except Exception:
                        pass

    # ── کانفیگ تصادفی ──────────────────────────────────────────────────────
    elif data == "random_cfg":
        if not await check_channel_membership(context.bot, uid):
            try: await q.edit_message_text(T("force_join_msg",lang), reply_markup=make_join_keyboard(lang), parse_mode="Markdown")
            except BadRequest: pass
            return
        reqs, cfgs = await DatabaseManager.check_rate_limit(uid)
        ok, err    = is_allowed(uid, prefs, reqs, cfgs)
        if not ok:
            try: await q.edit_message_text(err, reply_markup=make_back_keyboard(lang))
            except BadRequest: pass
            return
        # فقط یک کانفیگ لازم است — به‌جای ساخت کل لیست منطبق، با limit=1
        # مستقیماً یک نمونه‌ی تصادفی از reservoir sampling می‌گیریم.
        matches = CacheManager.get_filtered(prefs["protocol"], prefs["country"], limit=1)
        if not matches:
            try: await q.edit_message_text(T("no_configs",lang), reply_markup=make_back_keyboard(lang))
            except BadRequest: pass
            return
        cfg    = matches[0]
        # رفع باگ برخورد هش: کل رشته‌ی کانفیگ هش می‌شود، نه فقط ۶۴ کاراکتر اول.
        chash  = hashlib.sha256(cfg.encode()).hexdigest()[:16]
        display= cfg if len(cfg)<3000 else cfg[:3000]+"…"
        await DatabaseManager.increment_usage(uid, 1)
        try:
            await q.edit_message_text(
                f"🎲 *کانفیگ تصادفی:*\n\n`{display}`",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔄 یکی دیگر", callback_data="random_cfg"),
                     InlineKeyboardButton(T("feedback_prompt",lang), callback_data=f"feedback_{chash}")],
                    [InlineKeyboardButton(T("back",lang), callback_data="main_menu")],
                ]), parse_mode="Markdown")
        except BadRequest: pass

    # ── جستجوی کانفیگ ──────────────────────────────────────────────────────
    elif data == "search_configs":
        if not await check_channel_membership(context.bot, uid):
            try: await q.edit_message_text(T("force_join_msg",lang), reply_markup=make_join_keyboard(lang), parse_mode="Markdown")
            except BadRequest: pass
            return
        if uid != Config.ADMIN_ID:
            wait = await DatabaseManager.check_search_cooldown(uid)
            if wait > 0:
                try: await q.edit_message_text(T("search_cooldown",lang,sec=f"{wait:.0f}"), reply_markup=make_back_keyboard(lang))
                except BadRequest: pass
                return
        await DatabaseManager.set_user_pref(uid, "user_state", "waiting_search")
        try:
            await q.edit_message_text(
                T("enter_search",lang),
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(T("cancel",lang), callback_data="main_menu")]]),
                parse_mode="Markdown")
        except BadRequest: pass
        # مشابه fix بالا برای waiting_count: در گروه یک پیام ForceReply جدا
        # می‌فرستیم تا پاسخ متنی کاربر (عبارت جستجو) به‌عنوان ریپلای به بات
        # علامت‌گذاری شود و از گیت گروهی global_guard رد شود.
        if _is_group(update):
            try:
                await context.bot.send_message(
                    q.message.chat_id, T("enter_search", lang),
                    reply_to_message_id=q.message.message_id,
                    reply_markup=ForceReply(selective=True, input_field_placeholder="germany vless"))
            except BadRequest:
                # رفع باگ #27: همان منطق fallback بالا — اگر پیام مرجع حذف
                # شده باشد، بدون reply_to_message_id دوباره تلاش می‌شود، و
                # در بدترین حالت به ادمین اطلاع داده می‌شود که دوباره تلاش کند.
                try:
                    await context.bot.send_message(
                        q.message.chat_id, T("enter_search", lang),
                        reply_markup=ForceReply(selective=True, input_field_placeholder="germany vless"))
                except Exception:
                    try:
                        await context.bot.send_message(
                            q.message.chat_id,
                            "⚠️ پیام مرجع پیدا نشد — لطفاً دوباره روی دکمه بزنید یا مستقیم عبارت جستجو را بفرستید.")
                    except Exception:
                        pass

    # ── پروفایل کاربر ──────────────────────────────────────────────────────
    elif data == "my_profile":
        full = await DatabaseManager.get_user_full(uid)
        reqs, cfgs = await DatabaseManager.check_rate_limit(uid)
        vip_badge  = " ⭐ VIP" if prefs.get("is_vip") else ""
        text = (
            f"👤 *پروفایل{vip_badge}*\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"🆔 `{uid}`\n"
            f"📛 {full.get('first_name','—')}\n"
            f"📦 کل دانلود: `{prefs['total_downloads']:,}`\n"
            f"⚙️ پروتکل: `{prefs['protocol']}`\n"
            f"🌍 کشور: `{country_display(prefs['country'],lang)}`\n"
            f"🕐 آخرین فعالیت: `{(full.get('last_seen') or '—')[:16].replace('T',' ')}`\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📈 امروز: درخواست `{reqs}` | کانفیگ `{cfgs}`\n"
        )
        try:
            await q.edit_message_text(text, reply_markup=make_back_keyboard(lang), parse_mode="Markdown")
        except BadRequest: pass

    # ── Feedback ────────────────────────────────────────────────────────────
    elif data.startswith("feedback_"):
        chash = data[9:]
        try:
            await q.edit_message_text(
                T("feedback_prompt",lang),
                reply_markup=make_feedback_keyboard(chash, lang))
        except BadRequest: pass

    elif data.startswith("fb_"):
        parts  = data.split("_", 2)   # fb_not_work_HASH  or fb_slow_HASH  or fb_weak_HASH
        reason_map = {"not":"کار نمی‌کند","slow":"پینگ بالا","weak":"اتصال ضعیف"}
        r_key  = parts[1] if len(parts)>1 else "?"
        chash  = parts[2] if len(parts)>2 else "?"
        reason = reason_map.get(r_key, r_key)
        await DatabaseManager.add_feedback(uid, chash, reason)
        try: await q.edit_message_text(T("feedback_sent",lang), reply_markup=make_back_keyboard(lang))
        except BadRequest: pass

    # طبق درخواست صریح ادمین، کال‌بک‌های «کانفیگ‌های پینگ گرفته‌شده»
    # (tested_configs_txt, tested_configs_*) و «لینک ساب اختصاصی کاربر»
    # (my_sub_link) کاملاً حذف شدند — سیستم Real Ping Tester و پنل تحت وب
    # کاربر هر دو از بات برداشته شده‌اند. تنها پنل ادمین تحت وب باقی می‌ماند.

    # ── پنل ادمین ───────────────────────────────────────────────────────────
    elif data in ("admin_panel","admin_panel_2") and uid == Config.ADMIN_ID:
        page = 2 if data == "admin_panel_2" else 1
        try:
            await q.edit_message_text("👑 *پنل مدیریت*\n\nیک بخش را انتخاب کنید:",
                reply_markup=make_admin_keyboard(page), parse_mode="Markdown")
        except BadRequest: pass

    # ── دستورات ادمین از پنل ────────────────────────────────────────────────
    elif data.startswith("adm_") and uid == Config.ADMIN_ID:
        await _handle_admin_callback(q, data[4:], context)

    # ── Broadcast menu ──────────────────────────────────────────────────────
    elif data.startswith("bc_") and uid == Config.ADMIN_ID:
        await _handle_broadcast_callback(q, data[3:], context)

async def _handle_admin_callback(q, cmd: str, context: ContextTypes.DEFAULT_TYPE) -> None:
    """روتر داخلی callback های ادمین."""
    try:
        if cmd == "stats":
            await q.edit_message_text(await _build_stats_text(), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "health":
            await q.edit_message_text(await _build_health_text(), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "cache":
            await q.edit_message_text(await _build_cache_text(), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "reload":
            await q.edit_message_text("🔄 در حال بروزرسانی کش...", parse_mode="Markdown")
            count = await CacheManager.reload(bot=context.bot)
            await q.edit_message_text(
                f"✅ بروزرسانی کامل\n📦 `{count:,}` | 🔄 `{CacheManager._prev_delta}`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "sources":
            text, page, total = await _build_sources_text(1)
            await q.edit_message_text(text, parse_mode="Markdown",
                reply_markup=make_sources_pagination_keyboard(page, total))

        elif cmd.startswith("srcpage_"):
            try:
                requested_page = int(cmd.split("_", 1)[1])
            except (ValueError, IndexError):
                requested_page = 1
            text, page, total = await _build_sources_text(requested_page)
            await q.edit_message_text(text, parse_mode="Markdown",
                reply_markup=make_sources_pagination_keyboard(page, total))

        elif cmd == "top_sources":
            rows = await DatabaseManager.get_top_sources(8)
            lines = [f"⭐ `#{r[0]}` fail:`{r[2]}` {'🟢' if r[3] else '🔴'}\n`{r[1][:55]}...`" for r in rows]
            await q.edit_message_text("📈 *بهترین منابع:*\n\n"+"\n\n".join(lines), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "slow_sources":
            rows = await DatabaseManager.get_slow_sources(8)
            lines = [f"🐌 `#{r[0]}` fail:`{r[2]}` {'🟢' if r[3] else '🔴'}\n`{r[1][:55]}...`" for r in rows]
            await q.edit_message_text("🐌 *کندترین منابع:*\n\n"+"\n\n".join(lines), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "benchmark":
            await q.edit_message_text("🔬 Benchmark در حال اجرا...")
            m0 = _read_mem_mb(); c0 = _read_cpu_percent(); t0 = time.monotonic()
            prev = len(CacheManager._cache)
            cnt  = await CacheManager.reload(bot=context.bot)
            dt   = time.monotonic()-t0
            await q.edit_message_text(
                f"🔬 *Benchmark*\n\n"
                f"⏱ `{dt:.2f}s` | 📦 `{prev:,}`→`{cnt:,}` | 🔄 `{CacheManager._prev_delta}`\n"
                f"🧠 RAM: `{m0:.0f}`→`{_read_mem_mb():.0f}MB` | 💻 CPU: `{c0:.1f}%`\n"
                f"⚡ `{cnt/dt if dt>0 else 0:.0f}` cfg/s",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "users":
            total  = await DatabaseManager.count_total_users()
            active = await DatabaseManager.get_active_users(7)
            vips   = await DatabaseManager.get_vip_users()
            banned = await DatabaseManager.get_banned_users()
            text   = (f"👥 *کاربران*\n\n"
                      f"🔢 کل: `{total:,}`\n✅ فعال ۷روز: `{len(active)}`\n"
                      f"⭐ VIP: `{len(vips)}` | 🚫 Ban: `{len(banned)}`")
            await q.edit_message_text(text, parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "top_users":
            rows  = await DatabaseManager.get_top_users(10)
            lines = [f"{i+1}. `{r[0]}` @{r[1] or '—'} — `{r[3]:,}` cfg" for i,r in enumerate(rows)]
            await q.edit_message_text("🏆 *برترین کاربران:*\n\n"+"\n".join(lines), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "broadcast_menu":
            await q.edit_message_text("📤 *نوع Broadcast:*", reply_markup=make_broadcast_menu(), parse_mode="Markdown")

        elif cmd == "ban_menu":
            banned = await DatabaseManager.get_banned_users()
            lines  = [f"🚫 `{r[0]}` — {(r[2] or '---')[:20]}" for r in banned[:10]]
            await q.edit_message_text("🚫 *لیست مسدودان:*\n\n"+"\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "vip_menu":
            vips  = await DatabaseManager.get_vip_users()
            lines = [f"⭐ `{r[0]}` @{r[1] or '—'}" for r in vips[:10]]
            await q.edit_message_text("⭐ *VIP Users:*\n\n"+"\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "blacklist":
            ips   = await DatabaseManager.get_ip_blacklist()
            lines = [f"🔴 `{r[0]}` — {(r[1] or '---')[:20]}" for r in ips[:10]]
            await q.edit_message_text("🛡 *IP Blacklist:*\n\n"+"\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "logs":
            rows  = await DatabaseManager.get_logs(15)
            lines = [f"`[{r[0]}]` {r[3][:16]} — {r[2][:50]}" for r in rows]
            await q.edit_message_text("📋 *آخرین Logs:*\n\n"+"\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "errors":
            rows  = await DatabaseManager.get_logs(10, "ERROR")
            lines = [f"❌ `{r[3][:16]}` {r[2][:60]}" for r in rows]
            await q.edit_message_text("❌ *خطاهای اخیر:*\n\n"+"\n".join(lines or ["✅ خطایی نیست"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "rules":
            rules = await DatabaseManager.get_rules()
            lines = [f"{'✅' if r['enabled'] else '❌'} `#{r['id']}` {r['name']}\n  `IF {r['condition']} THEN {r['action']}`" for r in rules]
            await q.edit_message_text("⚙️ *Rules:*\n\n"+"\n\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "feedback":
            rows  = await DatabaseManager.get_feedback(10)
            lines = [f"`{r[0]}` @{r[1] or '—'} — {r[3] or '?'} `{r[4][:10]}`" for r in rows]
            await q.edit_message_text("💬 *Feedbacks:*\n\n"+"\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "backup":
            data = await DatabaseManager.backup_db()
            bio  = io.BytesIO(data); bio.seek(0)
            ts   = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M")
            try:
                await context.bot.send_document(
                    chat_id=Config.ADMIN_ID, document=bio,
                    filename=f"backup_{ts}.db", caption=f"💾 DB Backup — {ts}")
            finally:
                bio.close()
            await q.answer("💾 پشتیبان ارسال شد!", show_alert=True)

        elif cmd == "export":
            configs = CacheManager.get_filtered("ALL","ALL")
            bio     = io.BytesIO("\n".join(configs).encode()); bio.seek(0)
            ts      = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M")
            try:
                await context.bot.send_document(
                    chat_id=Config.ADMIN_ID, document=bio,
                    filename=f"configs_{ts}.txt", caption=f"📤 {len(configs):,} کانفیگ")
            finally:
                bio.close()
            await q.answer(f"📤 {len(configs):,} کانفیگ export شد!", show_alert=True)

        elif cmd == "cpu":
            cpu = _read_cpu_percent()
            await q.edit_message_text(f"💻 *CPU Usage*\n\n`{cpu:.1f}%`\n\n⚠️ هشدار بالای `{Config.CPU_ALERT_THRESHOLD:.0f}%`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "memory":
            mem = _read_mem_mb()
            await q.edit_message_text(f"🧠 *Memory Usage*\n\n`{mem:.1f} MB`\n\n⚠️ Optimizer: `>{Config.MEM_OPTIMIZER_MB}MB`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "version":
            await q.edit_message_text(
                f"📊 *Version Compare*\n\n"
                f"📦 کانفیگ فعلی: `{len(CacheManager._cache):,}`\n"
                f"🔄 آخرین تغییر: `{CacheManager._prev_delta or '---'}`\n"
                f"🕐 بروزرسانی: `{CacheManager._last_update}`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "github":
            rows  = await DatabaseManager.get_unnotified_github_sources()
            # (total count not needed here)
            lines = [f"⭐`{r[3]}` [{r[2]}]({r[1]})" for r in rows[:8]]
            await q.edit_message_text(
                f"🌐 *GitHub Sources*\n\nیافت‌نشده: `{len(rows)}`\n\n"+"\n".join(lines or ["(جدید نیست)"]),
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]),
                disable_web_page_preview=True)

        elif cmd == "analytics":
            active7  = await DatabaseManager.get_active_users(7)
            active30 = await DatabaseManager.get_active_users(30)
            inactive = await DatabaseManager.get_inactive_users(30)
            a7_lines = [f"  • `{r[0]}` @{r[1] or '—'} {(r[3] or '')[:10]}" for r in active7[:5]]
            text = (
                f"📊 *Analytics*\n\n"
                f"✅ فعال ۷ روز: `{len(active7)}`\n"
                f"✅ فعال ۳۰ روز: `{len(active30)}`\n"
                f"😴 غیرفعال ۳۰+ روز: `{len(inactive)}`\n\n"
                f"🆕 *فعال‌ترین اخیر:*\n" + "\n".join(a7_lines or ["(ندارد)"])
            )
            await q.edit_message_text(text, parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "cleanup":
            n = await DatabaseManager.cleanup_logs(7)
            await q.edit_message_text(f"🗑 *Cleanup*\n\n`{n}` لاگ قدیمی پاک شد.", parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "tasks":
            tasks = asyncio.all_tasks()
            names = [t.get_name() for t in tasks][:15]
            await q.edit_message_text(
                f"📦 *Async Tasks ({len(tasks)}):*\n\n`" + "\n".join(names) + "`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        # طبق درخواست صریح ادمین، دستور «pingstatus» حذف شد — سیستم Real
        # Ping Tester کاملاً از بات برداشته شده است.

        elif cmd in ("userinfo_prompt", "finduser_prompt", "findconfig_prompt"):
            prompts = {
                "userinfo_prompt":   "🔍 آیدی عددی یا یوزرنیم را بفرستید:",
                "finduser_prompt":   "🔍 بخشی از نام یا یوزرنیم را بفرستید:",
                "findconfig_prompt": "🔍 بخشی از کانفیگ را بفرستید:",
            }
            # قبلاً این پرامپت‌ها فقط پیام راهنما نشان می‌دادند ولی user_state واقعاً
            # ست نمی‌شد، پس user_message_handler هیچ‌وقت پاسخ بعدی ادمین را دریافت
            # نمی‌کرد و این دکمه‌ها عملاً کار نمی‌کردند — این‌جا رفع شد.
            state_map = {
                "userinfo_prompt":   "adm_waiting_userinfo",
                "finduser_prompt":   "adm_waiting_finduser",
                "findconfig_prompt": "adm_waiting_findconfig",
            }
            await DatabaseManager.set_user_pref(q.from_user.id, "user_state", state_map[cmd])
            await q.edit_message_text(prompts[cmd],
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))
            # همان رفع باگ گروهی بالا: اگر ادمین از داخل یک گروه پنل را باز
            # کرده باشد، یک پیام ForceReply جدا هم می‌فرستیم.
            if q.message and q.message.chat and q.message.chat.type in ("group","supergroup"):
                try:
                    await context.bot.send_message(
                        q.message.chat_id, prompts[cmd],
                        reply_to_message_id=q.message.message_id,
                        reply_markup=ForceReply(selective=True))
                except BadRequest:
                    # رفع باگ #27: fallback بدون reply_to_message_id، و در
                    # نهایت اطلاع‌رسانی صریح به ادمین در صورت شکست کامل.
                    try:
                        await context.bot.send_message(
                            q.message.chat_id, prompts[cmd],
                            reply_markup=ForceReply(selective=True))
                    except Exception:
                        try:
                            await context.bot.send_message(
                                q.message.chat_id,
                                "⚠️ پیام مرجع پیدا نشد — لطفاً دوباره روی دکمه بزنید یا مستقیم پاسخ را بفرستید.")
                        except Exception:
                            pass

    except BadRequest:
        pass
    except Exception as exc:
        logger.error(f"admin_callback {cmd}: {exc}", exc_info=True)

async def _handle_broadcast_callback(q, target: str, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        if target == "configs":
            configs = CacheManager.get_filtered("ALL","ALL", limit=10)
            uids    = await DatabaseManager.get_all_user_ids()
            msg_txt = "📦 *کانفیگ‌های جدید:*\n\n" + "\n\n".join(f"`{c}`" for c in configs[:5])
        else:
            target_map = {
                "all":      DatabaseManager.get_all_user_ids,
                "active":   lambda: DatabaseManager.get_active_users(7),
                "inactive": lambda: DatabaseManager.get_inactive_users(30),
                "vip":      DatabaseManager.get_vip_users,
            }
            if target not in target_map:
                await q.answer("❌ هدف نامعتبر"); return
            rows = await target_map[target]()
            uids = [r[0] if isinstance(r, (list,tuple)) else r for r in rows]
            msg_txt = "📢 *پیام ادمین*\n\nاین یک پیام عمومی است."

        await q.edit_message_text(f"📤 در حال ارسال به {len(uids):,} کاربر...")
        sent = failed = 0
        for uid in uids:
            try:
                await context.bot.send_message(uid, safe_truncate(msg_txt, 4090), parse_mode="Markdown")
                sent += 1
            except Exception:
                failed += 1
            await asyncio.sleep(0.05)
        await q.edit_message_text(
            f"✅ ارسال کامل\n📨 موفق: `{sent:,}` | ❌ ناموفق: `{failed:,}`",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))
    except BadRequest:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# پست کانال
# ═══════════════════════════════════════════════════════════════════════════════
async def _do_channel_post(context: ContextTypes.DEFAULT_TYPE) -> bool:
    """
    پست خودکار کانفیگ در کانال تلگرام (ویژگی مستقل از سیستم Ping Tester
    که حذف شد). طبق درخواست ادمین، دیگر اولویتی با «تست‌شده» وجود ندارد —
    مستقیماً از کش خام منابع (که همیشه در دسترس است) با همان فیلتر
    پروتکل/کشور کانال نمونه‌برداری می‌شود.
    """
    if not Config.CHANNEL_ID: return False

    filtered = CacheManager.get_channel_configs()
    if not filtered:
        logger.warning("⚠️  پست کانال: کانفیگی با فیلتر یافت نشد.")
        return False
    count           = min(Config.CHANNEL_POST_COUNT, len(filtered))
    sampled_configs = random.sample(filtered, count)
    header          = "📡 *بروزرسانی کانفیگ‌ها:*\n\n"

    payload = header + "\n\n".join(f"`{c}`" for c in sampled_configs)
    try:
        await context.bot.send_message(
            Config.CHANNEL_ID, safe_truncate(payload), parse_mode="Markdown")
        logger.info(f"✅ پست کانال ارسال شد ({count} کانفیگ).")
        return True
    except TelegramError as exc:
        logger.error(f"❌ پست کانال ناموفق: {exc}")
        await DatabaseManager.add_log("ERROR", str(exc), "channel_post")
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# Cron Jobs
# ═══════════════════════════════════════════════════════════════════════════════
async def cron_refresh(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        count = await CacheManager.reload(bot=context.bot)
        await SmartNotifier.check_all(context.bot)

        # Memory Optimizer را قبل از RuleEngine اجرا می‌کنیم و با یک flag
        # مشخص می‌کنیم که آیا همین دور کش را برش زده یا نه. اگر بله،
        # RuleEngine را برای همین دور رد می‌کنیم تا یک rule دستی با شرط
        # مشابه (مثلاً mem_mb > N) دوباره روی همان کش تازه‌برش‌خورده
        # برش نزند (تداخل دوگانه‌ی برش کش).
        optimizer_triggered = False
        mem = _read_mem_mb()
        if mem > Config.MEM_OPTIMIZER_MB and len(CacheManager._cache) > 1000:
            optimizer_triggered = True
            old = len(CacheManager._cache)
            CacheManager._cache = CacheManager._cache[:len(CacheManager._cache)*3//4]
            logger.info(f"🧹 Memory Optimizer: {old:,} → {len(CacheManager._cache):,} (RAM={mem:.0f}MB)")
            await DatabaseManager.add_log("INFO", f"Memory optimizer: {old}→{len(CacheManager._cache)}", "cron")

        if not optimizer_triggered:
            await RuleEngine.evaluate_all(context.bot)
        else:
            logger.debug("RuleEngine: این دور رد شد چون Memory Optimizer قبلاً کش را برش زد.")
    except Exception as exc:
        logger.error(f"cron_refresh: {exc}", exc_info=True)

async def cron_channel(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        await _do_channel_post(context)
    except Exception as exc:
        logger.error(f"cron_channel: {exc}", exc_info=True)

async def cron_cleanup(context: ContextTypes.DEFAULT_TYPE) -> None:
    """پاک‌سازی خودکار لاگ‌های قدیمی و رکوردهای قدیمی github_sources."""
    try:
        n = await DatabaseManager.cleanup_logs(days=7)
        if n > 0:
            logger.info(f"🗑 Auto-cleanup: {n} لاگ قدیمی پاک شد.")
        # رفع باگ #18 (رشد بی‌نهایت جدول github_sources)
        gh_n = await DatabaseManager.cleanup_github_sources()
        if gh_n > 0:
            logger.info(f"🗑 Auto-cleanup: {gh_n} رکورد قدیمی github_sources پاک شد.")
    except Exception as exc:
        logger.error(f"cron_cleanup: {exc}", exc_info=True)

async def cron_github_search(context: ContextTypes.DEFAULT_TYPE) -> None:
    """جستجوی GitHub برای منابع جدید."""
    try:
        found = await GitHubSourceFinder.search(context.bot)
        if found > 0:
            logger.info(f"🔍 GitHub: {found} منبع جدید یافت شد.")
    except Exception as exc:
        logger.error(f"cron_github: {exc}", exc_info=True)

async def cron_memory_leak_check(context: ContextTypes.DEFAULT_TYPE) -> None:
    """تشخیص Memory Leak — اگر RAM مداوم بالا رفت هشدار بده."""
    if not hasattr(cron_memory_leak_check, "_readings"):
        cron_memory_leak_check._readings = []
    mem = _read_mem_mb()
    cron_memory_leak_check._readings.append(mem)
    # فقط آخرین ۶ نمونه (۳۰ دقیقه با اجرای هر ۵ دقیقه)
    cron_memory_leak_check._readings = cron_memory_leak_check._readings[-6:]
    if len(cron_memory_leak_check._readings) >= 4:
        trend = cron_memory_leak_check._readings[-1] - cron_memory_leak_check._readings[0]
        if trend > 50:  # بیش از ۵۰MB رشد در ۳۰ دقیقه
            await SmartNotifier.notify(
                context.bot, "memory_leak",
                f"🚨 *Memory Leak احتمالی*\n\n"
                f"رشد: `+{trend:.1f}MB` در ۳۰ دقیقه\n"
                f"RAM فعلی: `{mem:.1f}MB`")

# ═══════════════════════════════════════════════════════════════════════════════
# Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════
async def post_init(app: Application) -> None:
    await DatabaseManager.init_db()
    await DatabaseManager.populate_default_sources()
    await DatabaseManager.start_write_worker()
    # بارگذاری IP Blacklist در حافظه
    blocked_ips = await DatabaseManager.load_ip_blacklist()
    IPBlacklist.load(blocked_ips)
    logger.info(f"🛡 {len(blocked_ips)} IP در لیست سیاه بارگذاری شد.")
    # شروع reload اولیه
    asyncio.create_task(CacheManager.reload())
    # ثبت دستورات
    await app.bot.set_my_commands([
        BotCommand("start",      "🏠 منوی اصلی"),
        BotCommand("help",       "❓ راهنما"),
        BotCommand("profile",    "👤 پروفایل من"),
        BotCommand("lang",       "🌐 تغییر زبان"),
        BotCommand("admin",      "👑 پنل ادمین"),
    ])
    await DatabaseManager.add_log("INFO", "Bot started v7.0", "post_init")
    logger.info("🚀 Bot v7.0 آماده — کش در حال بارگذاری...")

# ═══════════════════════════════════════════════════════════════════════════════
# main()
# ═══════════════════════════════════════════════════════════════════════════════
def main() -> None:
    Config.validate()

    app = (
        Application.builder()
        .token(Config.BOT_TOKEN)
        .post_init(post_init)
        .build()
    )

    jq = app.job_queue
    jq.run_repeating(cron_refresh,           interval=Config.CACHE_REFRESH_INTERVAL, first=90)
    jq.run_repeating(cron_channel,           interval=Config.CHANNEL_POST_INTERVAL,  first=180)
    jq.run_repeating(cron_cleanup,           interval=Config.AUTO_CLEANUP_INTERVAL,  first=3600)
    jq.run_repeating(cron_github_search,     interval=Config.GITHUB_SEARCH_INTERVAL, first=300)
    jq.run_repeating(cron_memory_leak_check, interval=300,                           first=600)

    # ── pre-handler جهانی (group=-1) ─────────────────────────────────────────
    app.add_handler(MessageHandler(filters.ALL,         global_guard), group=-1)
    app.add_handler(CallbackQueryHandler(global_guard),               group=-1)

    # ── دستورات کاربر ─────────────────────────────────────────────────────────
    app.add_handler(CommandHandler("start",   start_command))
    app.add_handler(CommandHandler("help",    help_command))
    app.add_handler(CommandHandler("lang",    lang_command))
    app.add_handler(CommandHandler("profile", profile_command))

    # ── دستورات ادمین ──────────────────────────────────────────────────────────
    app.add_handler(CommandHandler("admin",       admin_panel_command))
    app.add_handler(CommandHandler("stats",       admin_stats_cmd))
    app.add_handler(CommandHandler("health",      admin_health_cmd))
    app.add_handler(CommandHandler("reload",      admin_reload_cmd))
    app.add_handler(CommandHandler("force_update",admin_reload_cmd))
    app.add_handler(CommandHandler("vip",         admin_vip_cmd))
    app.add_handler(CommandHandler("ban",         admin_ban_cmd))
    app.add_handler(CommandHandler("unban",       admin_unban_cmd))
    app.add_handler(CommandHandler("broadcast",   admin_broadcast_cmd))
    app.add_handler(CommandHandler("addsource",   admin_addsource_cmd))
    app.add_handler(CommandHandler("removesource",admin_removesource_cmd))
    app.add_handler(CommandHandler("backup",      admin_backup_cmd))
    app.add_handler(CommandHandler("export",      admin_export_cmd))
    app.add_handler(CommandHandler("benchmark",   admin_benchmark_cmd))

    # ── روتر callback ──────────────────────────────────────────────────────────
    app.add_handler(CallbackQueryHandler(callback_router))

    # ── پیام‌های متنی ────────────────────────────────────────────────────────
    # رفع باگ «فلوی متنی (مثل وارد کردن تعداد کانفیگ یا عبارت جستجو) در گروه
    # کار نمی‌کند»: قبلاً این هندلر با filters.ChatType.PRIVATE محدود شده
    # بود، یعنی حتی اگر کاربر در گروه دقیقاً به بات ریپلای می‌کرد یا آن را
    # منشن می‌کرد، جواب متنی او (مثلاً عدد «50» بعد از زدن «دریافت کانفیگ»)
    # اصلاً به این تابع نمی‌رسید. حالا چت‌های گروهی هم مجازند — این ایمن
    # است چون global_guard (در group=-1، پیش از این هندلر) از قبل تضمین
    # کرده که پیام گروهی فقط وقتی به اینجا می‌رسد که واقعاً خطاب به بات
    # بوده (ریپلای به بات یا @mention)؛ بات هرگز به گفت‌وگوی معمولی اعضای
    # گروه که ربطی به آن ندارد پاسخ نمی‌دهد.
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND,
        user_message_handler))

    logger.info("🚀 Polling شروع شد...")
    app.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
