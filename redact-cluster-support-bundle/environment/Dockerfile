# Agent image. Nothing from tests/ or solution/ may ever be copied in here.
#
# Pin the base by digest so the image can never drift. To re-pin after changing the
# tag:  docker buildx imagetools inspect <image>:<tag>
# REPLACE this base with whatever your task actually needs.
FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e
 
WORKDIR /app
 
# tmux and asciinema are required in the final runtime image by the environment checklist.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      asciinema \
      ca-certificates \
      curl \
      tmux \
 && rm -rf /var/lib/apt/lists/*
 
# The service under repair and the bundles it reads. Stdlib only -- nothing to install.
COPY app/data/sluice/ /app/sluice/
COPY app/data/fixtures/ /app/fixtures/
 
ENV PYTHONPATH=/app

