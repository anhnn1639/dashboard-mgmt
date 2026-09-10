The seccomp_profile.json file is copied from Microsoft Playwright v1.62.0,
https://github.com/microsoft/playwright/blob/v1.62.0/utils/docker/seccomp_profile.json
under the Apache License 2.0. It retains the default-deny Docker profile with
the unprivileged namespace calls needed for Chromium's enabled sandbox.
See https://github.com/microsoft/playwright/blob/v1.62.0/LICENSE for the license.

Local modification (2026-09-10): the chroot syscall no longer depends on an
outer-container CAP_SYS_CHROOT capability. Chromium uses it inside its own
unprivileged user namespace; the container still drops ALL capabilities, runs
as UID 10002 with no-new-privileges and keeps Chromium's sandbox enabled.
The remaining seccomp rules are unchanged.
