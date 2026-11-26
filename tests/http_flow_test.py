"""Exercise the web entrypoint through a disposable PHP container."""

import http.cookiejar
import http.server
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def request(opener, url, data=None):
    payload = urllib.parse.urlencode(data).encode() if data is not None else None
    try:
        response = opener.open(url, data=payload, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read().decode("utf-8")


def csrf(body):
    match = re.search(r'name="csrf_token" value="([a-f0-9]{64})"', body)
    check(match is not None, "CSRF token missing")
    return match.group(1)


def main():
    image = os.environ.get("ACCESS_WEB_TEST_IMAGE", "access-web:ci")
    device_id = "00000000-0000-0000-0000-000000000002"
    event_id = "00000000-0000-0000-0000-000000000003"
    class GatewayHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("Authorization") != "Bearer test-token":
                status, data = 401, {}
            elif self.path == f"/devices/{device_id}":
                status, data = 200, {"id": device_id, "name": "<script>alert(1)</script>",
                                     "serialNumber": "reader", "active": True, "createdAt": "today"}
            elif self.path == f"/devices/{device_id}/events?limit=50":
                status, data = 200, [{"id": event_id, "credentialRef": "<img src=x onerror=alert(1)>",
                                      "eventType": "ENTRY", "classification": "ALLOWED"}]
            else:
                status, data = 503, {}
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    gateway = http.server.ThreadingHTTPServer(("0.0.0.0", 0), GatewayHandler)
    gateway_thread = threading.Thread(target=gateway.serve_forever, daemon=True)
    gateway_thread.start()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    password_hash = subprocess.check_output(
        ["docker", "run", "--rm", image, "php", "-r",
         "echo password_hash('test-password', PASSWORD_DEFAULT);"],
        text=True,
    )
    server = subprocess.Popen(
        ["docker", "run", "--rm", "-p", f"127.0.0.1:{port}:8000",
         "-e", f"ACCESS_WEB_PASSWORD_HASH={password_hash}",
         "-e", "ACCESS_GATEWAY_ADMIN_TOKEN=test-token",
         "--add-host", "host.docker.internal:host-gateway",
         "-e", f"ACCESS_GATEWAY_BASE_URL=http://host.docker.internal:{gateway.server_port}",
         image, "php", "-S", "0.0.0.0:8000", "-t", "public"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}/"
    try:
        cookies = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
        for _ in range(40):
            try:
                status, _, body = request(opener, url)
                break
            except (urllib.error.URLError, OSError):
                if server.poll() is not None:
                    raise RuntimeError("PHP container exited before serving")
                time.sleep(0.25)
        else:
            raise RuntimeError("PHP server did not start")

        check(status == 200 and "Acesso administrativo" in body, "Login page unavailable")
        token = csrf(body)
        before = next(cookie.value for cookie in cookies if cookie.name == "access_web_session")

        status, _, body = request(opener, url, {"action": "login", "password": "test-password"})
        check(status == 400 and "Formulário expirado" in body, "Missing CSRF accepted")
        status, _, body = request(opener, url, {"action": "login", "password": "wrong", "csrf_token": token})
        check(status == 200 and "Confira a senha" in body, "Invalid password accepted")
        status, _, body = request(opener, url, {"action": "login", "password": "test-password", "csrf_token": token})
        check(status == 200 and "UUID do dispositivo" in body, "Valid login failed")
        after = next(cookie.value for cookie in cookies if cookie.name == "access_web_session")
        check(before != after, "Session ID was not rotated on login")
        token = csrf(body)

        status, _, body = request(opener, url + "?device_id=invalid")
        check(status == 200 and "UUID de dispositivo válido" in body, "Invalid UUID reached gateway")
        status, _, body = request(opener, url + "?device_id=" + device_id)
        check(status == 200 and "&lt;script&gt;alert(1)&lt;/script&gt;" in body and
              "&lt;img src=x onerror=alert(1)&gt;" in body and "<script>alert(1)</script>" not in body,
              "Gateway-controlled HTML was not escaped")
        status, _, body = request(opener, url + "?device_id=00000000-0000-0000-0000-000000000001")
        check(status == 200 and "Não foi possível consultar o dispositivo" in body,
              "Gateway failure not handled")

        status, _, body = request(opener, url, {"action": "logout", "csrf_token": "0" * 64})
        check(status == 400 and "UUID do dispositivo" in body, "Invalid logout CSRF accepted")
        status, _, body = request(opener, url, {"action": "logout", "csrf_token": token})
        check(status == 200 and "Acesso administrativo" in body, "Logout did not clear session")
        status, _, body = request(opener, url + "?device_id=00000000-0000-0000-0000-000000000001")
        check(status == 200 and "Acesso administrativo" in body and "Dispositivo não encontrado" not in body,
              "Device query remained accessible after logout")

        token = csrf(body)
        for _ in range(4):
            status, _, _ = request(opener, url, {"action": "login", "password": "wrong", "csrf_token": token})
            check(status == 200, "Login blocked before fifth failure")
        status, headers, _ = request(opener, url, {"action": "login", "password": "wrong", "csrf_token": token})
        check(status == 429 and headers.get("Retry-After") == "900", "Fifth failure did not return 429")
        status, _, _ = request(opener, url, {"action": "login", "password": "test-password", "csrf_token": token})
        check(status == 429, "Correct password bypassed the block")
        print("HTTP flow tests passed")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
        gateway.shutdown()
        gateway.server_close()


if __name__ == "__main__":
    main()
