# Verifier image. Build context is this tests/ directory.
#
# The interpreter here must match environment/Dockerfile: the verifier executes
# the agent's submitted service with its own python, so a version older than the
# one the agent developed against would fail correct solutions.
#
# Fill in the digest before building:
#   docker pull public.ecr.aws/docker/library/python:3.13-slim-bookworm
#   docker inspect --format='{{index .RepoDigests 0}}' \
#       public.ecr.aws/docker/library/python:3.13-slim-bookworm
FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e

# Every verifier dependency is pinned and baked in; test.sh installs nothing.
# The packages go into a directory only root can read, outside the
# interpreter's own search path, and pip and its bundled installer are removed.
# The submitted service runs as another account, so the only modules it can
# import, whatever it does to its own path, are the standard library's.
RUN pip install --no-cache-dir --target /opt/verifier pytest==9.1.1 pytest-json-ctrf==0.5.2 \
 && chmod -R go-rwx /opt/verifier \
 && rm -rf "$(python -c 'import ensurepip, os; print(os.path.dirname(ensurepip.__file__))')" \
 && python -m pip uninstall -y pip

# The agent's service is executed as this unprivileged account so that the
# submitted code cannot read the verifier's own test file. The account owns
# nothing in the image; whatever it creates while a test runs is removed
# before the next one starts.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin sluicesvc

# Separate-mode verifiers get no upload of tests/, so the image owns /tests.
COPY . /tests/
RUN chmod 700 /tests && chmod +x /tests/test.sh

# Landing directory for the declared artifact. Harbor's upload fails if the
# parent directory does not already exist in this image.
RUN mkdir -p /app/sluice

WORKDIR /tests
