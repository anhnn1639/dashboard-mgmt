The seccomp_profile.json file is copied from Microsoft Playwright v1.62.0,
https://github.com/microsoft/playwright/blob/v1.62.0/utils/docker/seccomp_profile.json
under the Apache License 2.0. It retains the default-deny Docker profile with
the unprivileged namespace calls needed for Chromium's enabled sandbox.
See https://github.com/microsoft/playwright/blob/v1.62.0/LICENSE for the license.
