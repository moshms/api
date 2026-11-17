#!/usr/bin/env python3
import concurrent.futures
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("MC_SMOKE_BASE", "http://127.0.0.1:18086")
SETUP_TOKEN = os.environ.get("MC_SETUP_TOKEN", "setup-token")
ADMIN_PASSWORD = os.environ.get("MC_SMOKE_ADMIN_PASSWORD", "secret123456")


def client():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def call(opener, method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={
            **({"Content-Type": "application/json"} if data else {}),
            **(headers or {}),
        },
    )
    try:
        with opener.open(request) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = raw.decode(errors="replace")
        return error.code, parsed


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def setup_once(opener):
    return call(
        opener,
        "POST",
        "/api/v1/auth/setup",
        {
            "username": "admin",
            "password": ADMIN_PASSWORD,
            "setup_token": SETUP_TOKEN,
        },
    )


def main():
    status, body = call(client(), "GET", "/api/v1/auth/setup")
    expect(status == 200 and body["required"] is True, "setup should be required")
    expect(body.get("token_required") is True, "setup token should be required")

    status, _ = call(
        client(),
        "POST",
        "/api/v1/auth/setup",
        {"username": "admin", "password": ADMIN_PASSWORD},
    )
    expect(status == 401, "setup without token must fail")

    status, _ = call(
        client(),
        "POST",
        "/api/v1/auth/setup",
        {"username": "admin", "password": ADMIN_PASSWORD, "setup_token": "wrong"},
    )
    expect(status == 401, "setup with wrong token must fail")

    def setup_attempt(_):
        opener = client()
        return setup_once(opener), opener

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(setup_attempt, range(2)))
    statuses = sorted(result[0][0] for result in results)
    expect(statuses == [200, 409], f"setup race must yield 200/409, got {statuses}")
    admin = next(opener for (status, _), opener in results if status == 200)

    status, me = call(admin, "GET", "/api/v1/auth/me")
    expect(status == 200 and me["username"] == "admin", "admin session failed")
    admin_id = me["id"]

    status, role = call(
        admin,
        "POST",
        "/api/v1/roles",
        {"name": "Manager", "permissions": (1 << 1) | (1 << 2)},
    )
    expect(status == 201, f"create manager role failed: {status} {role}")
    role_id = role["id"]

    status, user = call(
        admin,
        "POST",
        "/api/v1/admin/users",
        {"username": "manager", "password": "manager12345", "role": "listener"},
    )
    expect(status == 201, f"create manager failed: {status} {user}")
    user_id = user["id"]

    status, _ = call(admin, "PUT", f"/api/v1/users/{user_id}/roles/{role_id}")
    expect(status == 204, "assign manager role failed")

    manager = client()
    status, _ = call(
        manager,
        "POST",
        "/api/v1/auth/login",
        {"username": "manager", "password": "manager12345"},
    )
    expect(status == 200, "manager login failed")

    status, _ = call(manager, "PATCH", f"/api/v1/admin/users/{user_id}", {"role": "admin"})
    expect(status == 403, "manage_users escalated itself to admin")

    status, _ = call(
        manager,
        "POST",
        "/api/v1/admin/users",
        {"username": "evil", "password": "evilpass12345", "role": "admin"},
    )
    expect(status == 403, "manage_users created an admin")

    status, roles = call(admin, "GET", "/api/v1/roles")
    expect(status == 200, "admin cannot list roles")
    admin_role = next(role for role in roles if role["permissions"] & 1)
    status, _ = call(manager, "PATCH", f"/api/v1/roles/{admin_role['id']}", {"permissions": 0})
    expect(status == 403, "manage_roles edited the administrator role")

    status, _ = call(
        manager,
        "POST",
        "/api/v1/roles",
        {"name": "LibrarySneak", "permissions": 1 << 10},
    )
    expect(status == 403, "manage_roles granted library permissions through a role")

    status, _ = call(
        admin,
        "PATCH",
        f"/api/v1/admin/users/{admin_id}",
        {"role": "listener"},
    )
    expect(status == 409, "last administrator could be demoted")

    bad = client()
    for attempt in range(5):
        status, _ = call(
            bad,
            "POST",
            "/api/v1/auth/login",
            {"username": "admin", "password": "wrong"},
        )
        expect(status == 401, f"failed login {attempt + 1} returned {status}")
    status, _ = call(
        bad,
        "POST",
        "/api/v1/auth/login",
        {"username": "admin", "password": ADMIN_PASSWORD},
    )
    expect(status == 429, "login rate limit did not trigger")

    status, credentials = call(admin, "GET", "/api/v1/auth/subsonic")
    expect(status == 200 and credentials["password"], "subsonic credentials missing")

    def subsonic(password):
        query = urllib.parse.urlencode(
            {
                "u": "admin",
                "p": password,
                "f": "json",
                "v": "1.16.1",
                "c": "security-smoke",
            }
        )
        with urllib.request.urlopen(BASE + "/rest/ping?" + query) as response:
            return json.loads(response.read())["subsonic-response"]["status"]

    expect(subsonic(ADMIN_PASSWORD) == "failed", "subsonic accepted the main password")
    expect(subsonic(credentials["password"]) == "ok", "subsonic rejected the app password")

    print("security smoke passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"security smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
