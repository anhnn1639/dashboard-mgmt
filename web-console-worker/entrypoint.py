"""Import only administrator-mounted public CA certificates into ephemeral NSS."""
import os
import subprocess
from pathlib import Path

root = Path('/home/worker/.pki/nssdb')
root.mkdir(parents=True, exist_ok=True)
subprocess.run(['certutil', '-N', '--empty-password', '-d', 'sql:' + str(root)], check=True, capture_output=True)
for index, certificate in enumerate(sorted(Path('/run/web-ca').glob('*.crt'))):
    if certificate.is_file() and not certificate.is_symlink() and certificate.stat().st_size <= 1024 * 1024:
        subprocess.run(['certutil', '-A', '-d', 'sql:' + str(root), '-n', 'console-ca-' + str(index),
                        '-t', 'C,,', '-i', str(certificate)], check=True, capture_output=True)
os.execvp('uvicorn', ['uvicorn', 'browser_worker:app', '--host', '0.0.0.0', '--port', '8081', '--no-access-log'])
