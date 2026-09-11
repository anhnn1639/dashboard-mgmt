"""Exercise deploy verification with a fake Docker CLI, never a daemon or data."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash") or ("C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else None)
TIMEOUT = "C:/Program Files/Git/usr/bin/timeout.exe" if os.name == "nt" else shutil.which("timeout")
MARKER = "/recordings/.operation-portal-storage.a123B456c789"


@unittest.skipUnless(BASH and Path(BASH).is_file() and TIMEOUT and Path(TIMEOUT).is_file(), "requires Bash and GNU timeout")
class DeploymentShellTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "deploy").mkdir()
        (self.root / "bin").mkdir()
        for name in ("deploy-dashboard.sh", "verify-recording-storage.sh", "verify-recording-storage.py", "verify-api-routes.py", "verify-guacamole.py"):
            shutil.copyfile(ROOT / "deploy" / name, self.root / "deploy" / name)
        for name in ("compose.yaml", "compose.test.yaml", "compose.external.yaml"):
            (self.root / name).touch()
        self.log = self.root / "calls.log"
        self.write_tool("git", '#!/bin/sh\ncase "$*" in "rev-parse HEAD") echo fixture-revision;; esac\n')
        self.write_tool("timeout", """#!/bin/sh
printf 'timeout:%s:%s\\n' "$1" "$2" >> "$FAKE_LOG"
[ "$1" = --kill-after=5s ] || exit 93
if [ -n "${FAKE_HANG:-}" ]; then
  shift 2
  exec '""" + Path(TIMEOUT).as_posix() + """' --kill-after=0.5s 1s "$@"
fi
exec '""" + Path(TIMEOUT).as_posix() + """' "$@"
""")
        self.write_tool("docker", r'''#!/bin/sh
printf 'docker:%s\n' "$*" >> "$FAKE_LOG"
case "$*" in *" exec "*) ;; *) exit 0;; esac
case "$*" in
  *"--interactive=true"*)
    source=$(cat)
    case "$*" in
      *"gosu ops python -"*)
        case "$source" in
          *'def verify_recording_storage('*) stage=read;;
          *'def verify_authentication('*) stage=guacamole;;
          *) exit 94;;
        esac
        [ "${FAKE_FAIL:-}" != "$stage" ] || exit 17
        ;;
      *"api python -"*)
        case "$source" in *'def verify_routes('*) ;; *) exit 94;; esac
        stage=routes
        ;;
      *) exit 95;;
    esac
    ;;
  *"--interactive=false"*)
    if IFS= read -r unexpected; then exit 96; fi
    case "$*" in
      *'mktemp /recordings/'*) stage=create;;
      *"guacd rm -f -- "*) stage=cleanup;;
      *"web-console python"*) stage=health;;
      *"dashboard node"*) stage=revision;;
      *) stage=other;;
    esac
    ;;
  *) exit 97;;
esac
printf 'stage:%s\n' "$stage" >> "$FAKE_LOG"
if [ "${FAKE_HANG:-}" = "$stage" ]; then
  trap '' TERM
  while :; do sleep 1; done
fi
case "$stage" in
  create)
    if [ "${FAKE_FAIL:-}" = invalid-marker ]; then echo /recordings/existing.guac;
    else echo /recordings/.operation-portal-storage.a123B456c789; fi
    ;;
  cleanup)
    case "$*" in *"guacd rm -f -- /recordings/.operation-portal-storage.a123B456c789") ;; *) exit 98;; esac
    ;;
esac
''')
        self.environment = os.environ.copy()
        # Git Bash interprets Windows drive paths in PATH itself; use cygpath to
        # supply one Unix-form entry without making production scripts Windows-specific.
        if os.name == "nt":
            converted = subprocess.run([BASH, "-c", 'cygpath -u "$1"', "convert", str(self.root / "bin")], check=True, text=True, capture_output=True)
            bin_path = converted.stdout.strip()
        else:
            bin_path = str(self.root / "bin")
        self.environment.update(FAKE_BIN=bin_path, FAKE_LOG=self.log.as_posix(), MSYS_NO_PATHCONV="1")

    def write_tool(self, name, contents):
        path = self.root / "bin" / name
        path.write_text(contents, encoding="utf-8", newline="\n")
        path.chmod(0o700)

    def run_script(self, script="verify-recording-storage.sh", **settings):
        environment = self.environment | settings
        result = subprocess.run([BASH, "-c", 'export PATH="$FAKE_BIN:$PATH"; exec sh "$@"', "deploy-fixture", str(self.root / "deploy" / script), "compose.test.yaml"], cwd=self.root, env=environment, input="unexpected caller input\n", text=True, capture_output=True, timeout=12)
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        return result, calls

    def test_success_preserves_source_stdin_and_closes_it_for_other_commands(self):
        result, calls = self.run_script("deploy-dashboard.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Deployment verified at commit fixture-revision", result.stdout)
        self.assertIn("[recording 1/3]", result.stdout)
        self.assertIn("[recording 2/3]", result.stdout)
        self.assertIn("[recording 3/3]", result.stdout)
        self.assertIn("stage:health", calls)
        self.assertIn("stage:guacamole", calls)
        self.assertIn("timeout:--kill-after=5s:75s", calls)
        self.assertEqual(calls.count("stage:cleanup"), 1)

    def test_api_read_failure_still_cleans_only_marker_and_fails_deployment(self):
        result, calls = self.run_script("deploy-dashboard.sh", FAKE_FAIL="read")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("API service user", result.stderr)
        self.assertIn("guacd rm -f -- " + MARKER, calls)
        self.assertNotIn("stage:revision", calls)
        self.assertNotIn("Deployment verified", result.stdout)

    def test_guacamole_failure_cannot_claim_deployment_success(self):
        result, calls = self.run_script("deploy-dashboard.sh", FAKE_FAIL="guacamole")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Guacamole JSON authentication and SSH/RDP protocols", result.stderr)
        self.assertNotIn("stage:health", calls)
        self.assertNotIn("Deployment verified", result.stdout)

    def test_invalid_marker_is_never_used_as_cleanup_target(self):
        result, calls = self.run_script(FAKE_FAIL="invalid-marker")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid recording readiness marker", result.stderr)
        self.assertNotIn("stage:cleanup", calls)
        self.assertNotIn("stage:read", calls)

    @unittest.skipIf(os.name == "nt", "POSIX process-group timeout is verified on Linux CI")
    def test_docker_ignoring_term_is_killed_and_stage_reported(self):
        result, calls = self.run_script(FAKE_HANG="create")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("[recording 1/3]", result.stdout)
        self.assertIn("failed or timed out", result.stderr)
        self.assertNotIn("stage:read", calls)

    @unittest.skipIf(os.name == "nt", "POSIX process-group timeout is verified on Linux CI")
    def test_later_verification_timeout_cannot_claim_deployment_success(self):
        result, calls = self.run_script("deploy-dashboard.sh", FAKE_HANG="health")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Web console health", result.stderr)
        self.assertIn("stage:cleanup", calls)
        self.assertNotIn("Deployment verified", result.stdout)


if __name__ == "__main__":
    unittest.main()
