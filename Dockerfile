# PathCutter CLI image. Offline, no database; mount your collection in and run any subcommand.
#   docker build -t pathcutter .
#   docker run --rm -v "$PWD/data:/data" pathcutter analyze /data/export.zip --html -o /data/report
FROM python:3.12-slim AS build
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir "build>=1.0" && python -m build --wheel --outdir /dist

FROM python:3.12-slim
# a non-root user: the container only reads a collection and writes a report, nothing privileged
RUN useradd --create-home --uid 10001 pathcutter
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
USER pathcutter
WORKDIR /data
ENTRYPOINT ["pathcutter"]
CMD ["--help"]
