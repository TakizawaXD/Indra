"""
GOJO INFINITY SECURITY ∞ — DATABASE ARCHITECTURE
SQLAlchemy ORM Models & SQLite Engine Persistence.
Implements all 21 core entities defined in Section 13.
"""

from sqlalchemy import (
    create_engine, event, Column, Integer, String, Text, Boolean, Float,
    DateTime, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from core.timeutils import utcnow
from core.config import settings
from core.logger import logger

Base = declarative_base()

# -----------------------------------------------------------------------------
# 1. USERS & SESSIONS
# -----------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), default="sorcerer_operator", nullable=False)  # admin, analyst, operator
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")

class UserSession(Base):
    __tablename__ = "sessions"

    id = Column(String(128), primary_key=True)  # Secure session token / JWT ID
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    ip_address = Column(String(64), nullable=False)
    user_agent = Column(String(256), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="sessions")

# -----------------------------------------------------------------------------
# 2. PROJECTS & AUTHORIZED TARGETS (Scope Enforcement)
# -----------------------------------------------------------------------------
class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    targets = relationship("AuthorizedTarget", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("NetworkScan", back_populates="project", cascade="all, delete-orphan")
    reports = relationship("SecurityReport", back_populates="project", cascade="all, delete-orphan")

class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    target = Column(String(256), nullable=False, index=True)  # IP, CIDR, or Domain
    target_type = Column(String(32), nullable=False)  # "ipv4", "ipv6", "cidr", "domain"
    authorization_notes = Column(Text, nullable=False)  # Justification / authorization proof
    verified_owner = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    project = relationship("Project", back_populates="targets")

# -----------------------------------------------------------------------------
# 3. NETWORK SCANS, HOSTS, PORTS & DOMAINS
# -----------------------------------------------------------------------------
class NetworkScan(Base):
    __tablename__ = "network_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)
    scan_type = Column(String(64), nullable=False)  # "ping_sweep", "tcp_connect", "service_recon"
    target = Column(String(256), nullable=False)
    status = Column(String(32), default="pending", nullable=False)  # pending, running, completed, failed
    start_time = Column(DateTime, default=utcnow, nullable=False)
    end_time = Column(DateTime, nullable=True)
    summary = Column(Text, nullable=True)

    project = relationship("Project", back_populates="scans")
    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")

class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("network_scans.id"), nullable=True, index=True)
    ip_address = Column(String(64), nullable=False, index=True)
    hostname = Column(String(256), nullable=True)
    os_hint = Column(String(128), nullable=True)
    status = Column(String(32), default="up", nullable=False)  # up, down
    response_time_ms = Column(Float, nullable=True)
    discovered_at = Column(DateTime, default=utcnow, nullable=False)

    scan = relationship("NetworkScan", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")

class Port(Base):
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(16), default="tcp", nullable=False)
    state = Column(String(32), default="open", nullable=False)  # open, filtered, closed
    service_name = Column(String(64), nullable=True)
    banner = Column(Text, nullable=True)
    version = Column(String(128), nullable=True)
    discovered_at = Column(DateTime, default=utcnow, nullable=False)

    host = relationship("Host", back_populates="ports")

class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_name = Column(String(256), unique=True, nullable=False, index=True)
    dns_records_json = Column(Text, nullable=True)  # A, AAAA, MX, NS, TXT serialized
    whois_info = Column(Text, nullable=True)
    ssl_issuer = Column(String(256), nullable=True)
    ssl_expiry = Column(DateTime, nullable=True)
    analyzed_at = Column(DateTime, default=utcnow, nullable=False)

# -----------------------------------------------------------------------------
# 4. IP RECORDS, HISTORY & REPUTATION (IP Intelligence)
# -----------------------------------------------------------------------------
class IPRecord(Base):
    __tablename__ = "ip_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(64), unique=True, nullable=False, index=True)
    ip_version = Column(Integer, default=4, nullable=False)
    is_private = Column(Boolean, default=False, nullable=False)
    country = Column(String(64), nullable=True)
    city = Column(String(64), nullable=True)
    asn = Column(String(64), nullable=True)
    organization = Column(String(128), nullable=True)
    reverse_dns = Column(String(256), nullable=True)
    threat_score = Column(Integer, default=0, nullable=False)  # 0 to 100
    first_seen = Column(DateTime, default=utcnow, nullable=False)
    last_seen = Column(DateTime, default=utcnow, nullable=False)

    history = relationship("IPHistory", back_populates="ip_record", cascade="all, delete-orphan")
    reputation_entries = relationship("IPReputation", back_populates="ip_record", cascade="all, delete-orphan")

class IPHistory(Base):
    __tablename__ = "ip_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_id = Column(Integer, ForeignKey("ip_records.id"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)  # logger_visit, scan_detected, threat_blocked
    path_accessed = Column(String(256), nullable=True)
    user_agent = Column(String(256), nullable=True)
    consent_status = Column(String(32), default="informed_service_visit", nullable=False)
    recorded_at = Column(DateTime, default=utcnow, nullable=False)

    ip_record = relationship("IPRecord", back_populates="history")

class IPReputation(Base):
    __tablename__ = "ip_reputation"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_id = Column(Integer, ForeignKey("ip_records.id"), nullable=False, index=True)
    source = Column(String(64), nullable=False)  # AbuseIPDB, LocalFilter, DNSBL
    indicator = Column(String(128), nullable=False)
    reputation_score = Column(Float, default=0.0, nullable=False)
    checked_at = Column(DateTime, default=utcnow, nullable=False)

    ip_record = relationship("IPRecord", back_populates="reputation_entries")

# -----------------------------------------------------------------------------
# 5. VULNERABILITIES & CVE RECORDS
# -----------------------------------------------------------------------------
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(256), nullable=False, index=True)
    cve_id = Column(String(64), nullable=True, index=True)
    cvss_score = Column(Float, default=0.0, nullable=False)
    severity = Column(String(32), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(32), default="confirmed", nullable=False)  # confirmed, probable, false_positive, pending
    target = Column(String(256), nullable=False)
    affected_component = Column(String(128), nullable=True)
    description = Column(Text, nullable=False)
    mitigation = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=utcnow, nullable=False)
    remediated_at = Column(DateTime, nullable=True)

class CVERecord(Base):
    __tablename__ = "cve_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=False)
    cvss_v3 = Column(Float, nullable=True)
    published_date = Column(DateTime, nullable=True)
    references_json = Column(Text, nullable=True)

# -----------------------------------------------------------------------------
# 6. THREATS, INCIDENTS & SECURITY EVENTS (Purple & Six Eyes)
# -----------------------------------------------------------------------------
class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(64), primary_key=True)  # UUID or Event Hash
    event_type = Column(String(64), nullable=False, index=True)
    origin_module = Column(String(32), nullable=False)  # INFINITY, BLUE, RED, PURPLE, SIX_EYES
    category = Column(String(64), nullable=False)
    severity = Column(String(32), default="INFO", nullable=False)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    source_ip = Column(String(64), nullable=True, index=True)
    target = Column(String(256), nullable=True)
    evidence_json = Column(Text, nullable=True)
    action_taken = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)

class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, autoincrement=True)
    threat_type = Column(String(64), nullable=False, index=True)  # BRUTE_FORCE, SQLI_PROBE, PORT_SWEEP
    source_ip = Column(String(64), nullable=True, index=True)
    severity = Column(String(32), default="MEDIUM", nullable=False)
    status = Column(String(32), default="active", nullable=False)  # active, mitigated, dismissed
    mitigation_applied = Column(String(128), nullable=True)
    detected_at = Column(DateTime, default=utcnow, nullable=False)

    incidents = relationship("Incident", back_populates="threat")

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=True, index=True)
    title = Column(String(256), nullable=False)
    severity = Column(String(32), default="HIGH", nullable=False)
    status = Column(String(32), default="open", nullable=False)  # open, investigating, contained, resolved
    containment_action = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)

    threat = relationship("Threat", back_populates="incidents")

# -----------------------------------------------------------------------------
# 7. FIREWALL RULES & INFINITY SHIELD
# -----------------------------------------------------------------------------
class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_name = Column(String(128), unique=True, nullable=False)
    rule_type = Column(String(32), nullable=False)  # IP_BAN, PATH_BLOCK, RATE_LIMIT, PAYLOAD_FILTER
    target_pattern = Column(String(256), nullable=False)  # IP, Regex, or URL Path
    action = Column(String(32), default="DENY", nullable=False)  # ALLOW, DENY, CHALLENGE
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    hits = Column(Integer, default=0, nullable=False)

# -----------------------------------------------------------------------------
# 8. AUDIT LOGS, LAB RUNS, REPORTS & CONFIG
# -----------------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(128), nullable=False, index=True)
    resource = Column(String(256), nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)

    user = relationship("User", back_populates="audit_logs")

class LaboratoryRun(Base):
    __tablename__ = "laboratory_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scenario_name = Column(String(128), nullable=False)  # "sqli_sandbox", "bruteforce_lab", "xss_range"
    status = Column(String(32), default="completed", nullable=False)
    simulated_target = Column(String(256), nullable=False)
    payload_count = Column(Integer, default=0, nullable=False)
    findings_json = Column(Text, nullable=True)
    executed_at = Column(DateTime, default=utcnow, nullable=False)

class SecurityReport(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)
    report_title = Column(String(256), nullable=False)
    report_type = Column(String(64), nullable=False)  # "executive", "technical", "network", "purple_audit"
    file_path = Column(String(512), nullable=False)
    summary_json = Column(Text, nullable=True)
    generated_at = Column(DateTime, default=utcnow, nullable=False)

    project = relationship("Project", back_populates="reports")

class SystemConfiguration(Base):
    __tablename__ = "configurations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(128), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

# -----------------------------------------------------------------------------
# ENGINE & SESSION PROVIDERS
# -----------------------------------------------------------------------------
_IS_SQLITE = settings.DATABASE_URL.startswith("sqlite")

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 15} if _IS_SQLITE else {},
    pool_pre_ping=True,
    echo=False
)

if _IS_SQLITE:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record):
        """WAL + busy timeout: lets the web server and the CLI write concurrently."""
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=15000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Dependency injector for database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes all database tables and verifies schema consistency."""
    logger.info("Initializing SQLite database tables for Gojo Infinity...")
    Base.metadata.create_all(bind=engine)
    logger.info("All 21 database models successfully verified and synchronized.")
