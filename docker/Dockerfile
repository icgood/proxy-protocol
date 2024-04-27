FROM python:3.12-slim

WORKDIR /src
COPY . .

RUN pip install hatch
RUN hatch env create docker

ENTRYPOINT ["hatch", "-e", "docker", "run", "proxyprotocol-server"]
CMD ["--help"]
