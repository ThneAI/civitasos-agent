FROM python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1

WORKDIR /opt/civitas
COPY --chown=65532:65532 participant_runner.py /opt/civitas/participant_runner.py
USER 65532:65532

ENTRYPOINT ["python", "-I", "/opt/civitas/participant_runner.py"]
