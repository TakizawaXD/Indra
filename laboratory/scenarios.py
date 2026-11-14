"""
GOJO INFINITY SECURITY ∞ — ATTACK LAB SCENARIOS & DATA
Provides realistic, safe, isolated cybersecurity testbeds for practice and validation.
No external network calls, completely offline and contained.
"""


LAB_SCENARIOS = {
    "sqli_lab": {
        "id": "sqli_lab",
        "title": "Cursed Relic SQL Injection Sandbox",
        "category": "INJECTION",
        "difficulty": "Easy to Medium",
        "description": "Simulates a vulnerable search endpoint accepting raw query strings. Used to test detection by Infinity Shield and validation by Red Operations.",
        "vulnerable_param": "query",
        "mock_db": [
            {"id": 1, "name": "Prison Realm", "grade": "Special", "sealed": True},
            {"id": 2, "name": "Playful Cloud", "grade": "Special", "sealed": False},
            {"id": 3, "name": "Inverted Spear of Heaven", "grade": "Special", "sealed": True},
            {"id": 4, "name": "Dragon Bone", "grade": "Grade 1", "sealed": False}
        ]
    },
    "xss_lab": {
        "id": "xss_lab",
        "title": "Jujutsu High Reflected XSS Sandbox",
        "category": "CLIENT_SIDE",
        "difficulty": "Easy",
        "description": "Simulates a user profile or greeting endpoint that reflects user inputs without HTML entity encoding.",
        "vulnerable_param": "name"
    },
    "auth_lab": {
        "id": "auth_lab",
        "title": "Barrier Bypass & Weak Authentication Lab",
        "category": "AUTHENTICATION",
        "difficulty": "Medium",
        "description": "Simulates weak password policies and absence of rate limiting on login attempts to practice Infinity Shield defense activation.",
        "weak_accounts": {
            "operator": "password123",
            "admin": "admin2026",
            "guest": "guest"
        }
    },
    "path_traversal_lab": {
        "id": "path_traversal_lab",
        "title": "Tengen Barrier File Read Range",
        "category": "PATH_TRAVERSAL",
        "difficulty": "Medium",
        "description": "Simulates an insecure file download parameter vulnerable to directory traversal (../).",
        "vulnerable_param": "file"
    }
}
