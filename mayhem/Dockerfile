# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds ON TOP of the org C/C++ base image
# (ghcr.io/savantenvs/base). The base provides debian + clang/llvm + libFuzzer + the build-contract
# ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/STANDALONE_FUZZ_MAIN/SRC); this only adds the
# per-commit binexport build.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       -t binexport-commit:test .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake as ENV (empty breaks clang).
ARG SOURCE_DATE_EPOCH
# Declare SANITIZER_FLAGS without a default so an unset arg lets the base ENV flow through.
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# binexport builds with CMake and pulls abseil + protobuf via FetchContent (boost is vendored in the
# repo's boost_parts/; googletest is only fetched when testing is enabled, which we keep OFF). Bake the
# pinned dependency source trees so build.sh re-runs air-gapped: it points CMake's
# FETCHCONTENT_SOURCE_DIR_* at these and sets FETCHCONTENT_FULLY_DISCONNECTED=ON. Versions match
# cmake/BinExportDeps.cmake: abseil commit ce1a8f1 (2026-07-20), protobuf v35.1.
USER root
RUN if ! command -v cmake >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1 \
      || ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then \
      [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true; \
      apt-get update && apt-get install -yq --no-install-recommends \
        cmake make pkg-config build-essential git curl python3 ca-certificates \
      && rm -rf /var/lib/apt/lists/*; \
    fi \
    && git clone https://github.com/abseil/abseil-cpp.git /opt/absl-cache \
    && git -C /opt/absl-cache checkout ce1a8f1ec1793e5cb9d7fffa281efdfea5dd8035 \
    && mkdir -p /opt/protobuf-cache \
    && curl -fsSL https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protobuf-35.1.tar.gz \
       | tar -xz --strip-components=1 -C /opt/protobuf-cache \
    && chmod -R a+rX /opt/absl-cache /opt/protobuf-cache
USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history) is
# copied to /mayhem; build.sh builds in place.
ENV SRC=/mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# Run binexport's behavioral oracle at build time (a failing suite fails the image build).
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
