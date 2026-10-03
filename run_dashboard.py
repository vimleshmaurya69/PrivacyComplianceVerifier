from pathlib import Path
import shutil
import subprocess
import sys
import webbrowser
import http.server
import socketserver
import threading
from urllib.parse import unquote, urlsplit

PORT = 8080
ROOT_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = ROOT_DIR / "dashboard"
DIST_DIR = (DASHBOARD_DIR / "dist").resolve()
DATA_DIR = (ROOT_DIR / "data").resolve()
ALLOWED_DATA_DIRS = (
    (DATA_DIR / "analysis").resolve(),
    (DATA_DIR / "output").resolve(),
)
DENIED_PATH = ROOT_DIR / ".dashboard-access-denied"


def _safe_child(root: Path, relative_path: str):
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _safe_dashboard_data_path(relative_path: str):
    candidate = _safe_child(DATA_DIR, relative_path)
    if candidate is None:
        return None
    for allowed_root in ALLOWED_DATA_DIRS:
        try:
            candidate.relative_to(allowed_root)
            return candidate
        except ValueError:
            continue
    return None

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        clean_path = unquote(urlsplit(path).path)

        # Route /data/* to the root data/ folder
        if clean_path.startswith('/data/'):
            candidate = _safe_dashboard_data_path(clean_path[6:])
            return str(candidate if candidate is not None else DENIED_PATH)

        # Route frontend requests to dashboard/dist/
        rel = clean_path.lstrip('/')
        if not rel or rel == 'index.html':
            return str(DIST_DIR / 'index.html')

        candidate = _safe_child(DIST_DIR, rel)
        if candidate is not None and candidate.is_file():
            return str(candidate)

        # SPA fallback for client-side routing
        return str(DIST_DIR / 'index.html')

    def log_message(self, format, *args):
        # Suppress noisy logs
        pass

def start_server(open_browser=False):
    try:
        httpd = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), DashboardHandler)
    except OSError as exc:
        print(f"ERROR: Cannot start dashboard on port {PORT}: {exc}")
        print("Close any existing dashboard window/server and try again.")
        return False

    with httpd:
        if open_browser:
            timer = threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{PORT}/"))
            timer.daemon = True
            timer.start()

        print("=" * 60)
        print("Privacy Compliance Verification Framework — Dashboard")
        print("=" * 60)
        print(f"Server running at: http://localhost:{PORT}/")
        print("Press Ctrl+C to stop.")
        print("=" * 60)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")
    return True


def _dashboard_build_required():
    index_file = DIST_DIR / "index.html"
    if not index_file.exists():
        return True

    build_time = index_file.stat().st_mtime
    watched_paths = [
        DASHBOARD_DIR / "src",
        DASHBOARD_DIR / "index.html",
        DASHBOARD_DIR / "package.json",
        DASHBOARD_DIR / "vite.config.js",
    ]
    for watched_path in watched_paths:
        if watched_path.is_file() and watched_path.stat().st_mtime > build_time:
            return True
        if watched_path.is_dir():
            for source_file in watched_path.rglob("*"):
                if source_file.is_file() and source_file.stat().st_mtime > build_time:
                    return True
    return False


def build_dashboard():
    node = shutil.which("node")
    local_vite = DASHBOARD_DIR / "node_modules" / "vite" / "bin" / "vite.js"
    if node and local_vite.exists():
        command = [node, str(local_vite), "build"]
    else:
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm:
            raise RuntimeError("Node/npm is unavailable and the dashboard requires a rebuild")
        command = [npm, "run", "build"]

    completed = subprocess.run(command, cwd=DASHBOARD_DIR, check=False)
    if completed.returncode != 0:
        raise RuntimeError("Dashboard build failed; the server was not started with stale assets")

if __name__ == "__main__":
    if _dashboard_build_required():
        print("Building dashboard assets...")
        try:
            build_dashboard()
        except RuntimeError as exc:
            print(f"ERROR: {exc}")
            sys.exit(1)

    if not start_server(open_browser=True):
        sys.exit(1)
