# Verifier image. Build context is this tests/ directory.
FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e

# Every verifier dependency is pinned and baked in. test.sh installs nothing.
RUN pip install --no-cache-dir pytest==9.1.1 pytest-json-ctrf==0.5.2

# The agent's service is executed as this unprivileged account so that the
# submitted code cannot read the verifier's own test file.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin sluicesvc \
 && mkdir -p /run/sluice \
 && chown sluicesvc:sluicesvc /run/sluice

# Separate-mode verifiers get no upload of tests/, so the image owns /tests.
COPY . /tests/
RUN chmod 700 /tests && chmod +x /tests/test.sh

# Landing directory for the declared artifact. Harbor's upload fails if the
# parent directory does not already exist in this image.
RUN mkdir -p /app/sluice

WORKDIR /tests
