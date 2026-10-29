# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE=python:3.12-slim

FROM ${PYTHON_IMAGE} AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /bin/uv
# Extras to install; default postgres,mcp. Adapters add e.g. EXTRAS=postgres,mcp,langgraph.
# crewai is refused: it conflicts with other extras in the lock (see pyproject uv conflicts).
ARG EXTRAS=postgres,mcp
RUN case ",${EXTRAS}," in *crewai*) \
      echo "EXTRAS must not contain crewai: it conflicts with mcp/openai/all/adk; build a separate image" >&2; exit 1;; \
    esac
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN uv build --wheel --out-dir /dist \
 && uv venv /opt/venv \
 && W="$(ls /dist/*.whl)" \
 && if [ -n "${EXTRAS}" ]; then SPEC="a2a-gateway[${EXTRAS}] @ file://${W}"; else SPEC="${W}"; fi \
 && VIRTUAL_ENV=/opt/venv uv pip install "${SPEC}"

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
