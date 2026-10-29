# syntax=docker/dockerfile:1
# python:3.12-slim, pinned by digest (multi-arch index; refresh with
# `docker buildx imagetools inspect python:3.12-slim`).
ARG PYTHON_IMAGE=python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

FROM ${PYTHON_IMAGE} AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /bin/uv
# Extras to install; default postgres,mcp. Adapters add e.g. EXTRAS=postgres,mcp,langgraph.
# crewai is refused: it conflicts with other extras in the lock (see pyproject uv conflicts).
ARG EXTRAS=postgres,mcp
RUN E="$(printf %s "${EXTRAS}" | tr '[:upper:]' '[:lower:]')"; \
    case ",${E}," in *crewai*) \
      echo "EXTRAS must not contain crewai: it conflicts with mcp/openai/all/adk; build a separate image" >&2; exit 1;; \
    esac
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
ENV UV_PYTHON_DOWNLOADS=never
# Exactly the versions uv.lock pins (with their hashes): the dependencies are exported from
# the lock (--locked: a lock that no longer matches pyproject.toml fails the build) and
# installed first; the project wheel goes in after them without dependencies.
RUN set -e; \
    ARGS=""; \
    for x in $(printf %s "${EXTRAS}" | tr '[:upper:]' '[:lower:]' | tr ',' ' '); do ARGS="${ARGS} --extra ${x}"; done; \
    uv export --locked --no-dev --no-emit-project ${ARGS} > /tmp/req.txt; \
    uv venv --python /usr/local/bin/python3.12 /opt/venv; \
    VIRTUAL_ENV=/opt/venv uv pip install --require-hashes -r /tmp/req.txt; \
    uv build --wheel --out-dir /dist; \
    VIRTUAL_ENV=/opt/venv uv pip install --no-deps /dist/*.whl

FROM ${PYTHON_IMAGE}
RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin a2agw \
 && mkdir -p /config /data && chown a2agw:a2agw /data
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    A2AGW_DB_URL="sqlite+aiosqlite:////data/a2agw.db"
USER 10001
WORKDIR /config
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/a2agw/admin/healthz', timeout=3).status == 200 else 1)"]
ENTRYPOINT ["a2agw"]
CMD ["serve", "-c", "/config/a2agw.yaml", "--host", "0.0.0.0", "--port", "8000"]
