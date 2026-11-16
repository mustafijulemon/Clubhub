import hashlib
import hmac
import secrets
import sqlite3
from pathlib import Path


DATABASE_PATH = Path(__file__).with_name("clubhub.db")
DEFAULT_CLUBS = (
    "Debating Club of BUBT",
    "Cultural Club of BUBT",
    "Sports Club of BUBT",
    "IT Club of BUBT",
)
PASSWORD_ITERATIONS = 310_000


class ClubHubDatabase:
    def __init__(self, path=DATABASE_PATH):
        self.path = Path(path)

    def connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS authority (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    password_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS clubs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    club_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    username TEXT UNIQUE COLLATE NOCASE,
                    password_hash TEXT,
                    general_secretary TEXT NOT NULL DEFAULT '',
                    president TEXT NOT NULL DEFAULT '',
                    moderator TEXT NOT NULL DEFAULT '',
                    co_moderator TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    club_id INTEGER NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    student_id TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    department TEXT NOT NULL,
                    intake TEXT NOT NULL,
                    section TEXT NOT NULL,
                    email TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    blood_group TEXT NOT NULL,
                    meetings_attended INTEGER NOT NULL DEFAULT 0 CHECK (meetings_attended >= 0),
                    achievements INTEGER NOT NULL DEFAULT 0 CHECK (achievements >= 0)
                );
                CREATE TABLE IF NOT EXISTS event_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    club_id INTEGER NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
                    event_name TEXT NOT NULL,
                    event_date TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    venue TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Pending'
                        CHECK (status IN ('Pending', 'Approved', 'Rejected')),
                    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            connection.executemany(
                "INSERT OR IGNORE INTO clubs (club_name) VALUES (?)",
                ((name,) for name in DEFAULT_CLUBS),
            )

    @staticmethod
    def _hash_password(password):
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
        )
        return f"{salt.hex()}:{digest.hex()}"

    @staticmethod
    def _verify_password(password, encoded):
        try:
            salt_hex, digest_hex = encoded.split(":", 1)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
        except (ValueError, AttributeError):
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
        )
        return hmac.compare_digest(actual, expected)

    @staticmethod
    def _required_text(value, label):
        clean = value.strip() if isinstance(value, str) else ""
        if not clean:
            raise ValueError(f"{label} is required.")
        return clean

    def authority_exists(self):
        with self.connect() as connection:
            return connection.execute("SELECT 1 FROM authority LIMIT 1").fetchone() is not None

    def create_authority(self, username, password):
        username = self._required_text(username, "Username")
        if len(password) < 12:
            raise ValueError("Authority password must be at least 12 characters.")
        with self.connect() as connection:
            if connection.execute("SELECT 1 FROM authority LIMIT 1").fetchone():
                raise ValueError("Authority setup has already been completed.")
            connection.execute(
                "INSERT INTO authority (username, password_hash) VALUES (?, ?)",
                (username, self._hash_password(password)),
            )

    def authenticate(self, role, username, password):
        if not username or not password:
            return None
        with self.connect() as connection:
            if role == "authority":
                row = connection.execute(
                    "SELECT username, password_hash FROM authority WHERE username = ?",
                    (username.strip(),),
                ).fetchone()
                if row and self._verify_password(password, row["password_hash"]):
                    return {"role": "authority", "username": row["username"]}
                return None
            row = connection.execute(
                """SELECT id, club_name, username, password_hash
                   FROM clubs WHERE username = ? AND password_hash IS NOT NULL""",
                (username.strip(),),
            ).fetchone()
            if row and self._verify_password(password, row["password_hash"]):
                return {
                    "role": "club",
                    "club_id": row["id"],
                    "club_name": row["club_name"],
                    "username": row["username"],
                }
        return None

    def list_clubs(self):
        with self.connect() as connection:
            return connection.execute(
                """SELECT id, club_name, username, general_secretary, president,
                          moderator, co_moderator
                   FROM clubs ORDER BY club_name COLLATE NOCASE"""
            ).fetchall()

    def set_club_credentials(self, club_id, username, password):
        username = self._required_text(username, "Username")
        if len(password) < 10:
            raise ValueError("Club password must be at least 10 characters.")
        try:
            with self.connect() as connection:
                cursor = connection.execute(
                    """UPDATE clubs SET username = ?, password_hash = ?
                       WHERE id = ?""",
                    (username, self._hash_password(password), club_id),
                )
                if cursor.rowcount != 1:
                    raise ValueError("Select a valid club.")
        except sqlite3.IntegrityError as error:
            raise ValueError("That username is already assigned to another club.") from error

    def add_member(self, club_id, member):
        keys = (
            "name", "student_id", "department", "intake", "section",
            "email", "phone", "blood_group",
        )
        values = [self._required_text(member.get(key), key.replace("_", " ").title()) for key in keys]
        values[-1] = values[-1].upper()
        try:
            with self.connect() as connection:
                connection.execute(
                    """INSERT INTO members
                       (club_id, name, student_id, department, intake, section,
                        email, phone, blood_group)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (club_id, *values),
                )
        except sqlite3.IntegrityError as error:
            raise ValueError("Student ID is already registered.") from error

    def list_members(self, club_id=None):
        query = """SELECT members.id, clubs.club_name, members.name, members.student_id,
                          members.department, members.intake, members.section,
                          members.email, members.phone, members.blood_group,
                          members.meetings_attended, members.achievements
                   FROM members JOIN clubs ON clubs.id = members.club_id"""
        parameters = ()
        if club_id is not None:
            query += " WHERE members.club_id = ?"
            parameters = (club_id,)
        query += " ORDER BY members.name COLLATE NOCASE"
        with self.connect() as connection:
            return connection.execute(query, parameters).fetchall()

    def search_blood_group(self, blood_group):
        with self.connect() as connection:
            return connection.execute(
                """SELECT members.id, clubs.club_name, members.name, members.student_id,
                          members.department, members.phone, members.blood_group
                   FROM members JOIN clubs ON clubs.id = members.club_id
                   WHERE UPPER(members.blood_group) = ?
                   ORDER BY members.name COLLATE NOCASE""",
                (blood_group.strip().upper(),),
            ).fetchall()

    def add_event_request(self, club_id, event_name, event_date, event_time, venue):
        values = [
            self._required_text(event_name, "Event name"),
            self._required_text(event_date, "Event date"),
            self._required_text(event_time, "Event time"),
            self._required_text(venue, "Venue"),
        ]
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO event_requests (club_id, event_name, event_date, event_time, venue)
                   VALUES (?, ?, ?, ?, ?)""",
                (club_id, *values),
            )

    def list_event_requests(self, club_id=None):
        query = """SELECT event_requests.id, clubs.club_name, event_requests.event_name,
                          event_requests.event_date, event_requests.event_time,
                          event_requests.venue, event_requests.status,
                          event_requests.requested_at
                   FROM event_requests JOIN clubs ON clubs.id = event_requests.club_id"""
        parameters = ()
        if club_id is not None:
            query += " WHERE event_requests.club_id = ?"
            parameters = (club_id,)
        query += " ORDER BY event_requests.requested_at DESC, event_requests.id DESC"
        with self.connect() as connection:
            return connection.execute(query, parameters).fetchall()

    def update_event_status(self, event_id, status):
        if status not in {"Approved", "Rejected"}:
            raise ValueError("Event status must be Approved or Rejected.")
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE event_requests SET status = ? WHERE id = ?",
                (status, event_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Select a valid event request.")

    def update_member_stats(self, club_id, member_id, meetings, achievements):
        try:
            meetings = int(meetings)
            achievements = int(achievements)
        except (TypeError, ValueError) as error:
            raise ValueError("Meetings and achievements must be whole numbers.") from error
        if meetings < 0 or achievements < 0:
            raise ValueError("Meetings and achievements cannot be negative.")
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE members SET meetings_attended = ?, achievements = ?
                   WHERE id = ? AND club_id = ?""",
                (meetings, achievements, member_id, club_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Select a valid member from your club.")

