# syntax=docker/dockerfile:1
# Stage 1: build and unit-test the C packet library.
FROM python:3.12-slim AS cbuild
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake ninja-build gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY csrc/ csrc/
RUN cmake -S csrc -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DNX_WERROR=ON \
 && cmake --build build \
 && ctest --test-dir build --output-on-failure

# Stage 2: runtime image, non-root.
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 ethtool git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 nexus \
 && mkdir /lab && chown nexus:nexus /lab
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY --from=cbuild /src/build/libnexus_pkt.so src/nexus/_lib/libnexus_pkt.so
RUN pip install --no-cache-dir . \
 && python -c "from nexus import pcap; assert pcap.load_library(), pcap.library_status()"
COPY examples/ examples/
COPY scripts/ scripts/
USER nexus
ENV GIT_AUTHOR_NAME=nexus GIT_AUTHOR_EMAIL=nexus@localhost \
    GIT_COMMITTER_NAME=nexus GIT_COMMITTER_EMAIL=nexus@localhost
ENTRYPOINT ["nexus"]
CMD ["--help"]
