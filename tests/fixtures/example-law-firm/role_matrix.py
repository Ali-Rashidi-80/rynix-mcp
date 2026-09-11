# Role deny matrix excerpt — golden fixture from example law-firm application smoke tests
# Source: backend/tests/test_role_production_smoke.py

ROLE_DENY_SAMPLES = [
    ("GET", "/finance/cases/summary", ["LAWYER", "CLIENT"]),
    ("GET", "/system/docker/containers", ["LAWYER", "CLIENT", "CEO"]),
]

ROLE_ALLOW_SAMPLES = [
    ("GET", "/cases/", ["LAWYER", "CLIENT", "ADMIN"]),
]
