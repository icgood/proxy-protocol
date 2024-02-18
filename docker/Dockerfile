FROM python:3.12-alpine

WORKDIR /src
COPY . .

RUN pip install -U pip wheel setuptools hatch typing-extensions

RUN apk --update add --virtual build-dependencies python3-dev build-base \
  && hatch env create docker \
  && apk del build-dependencies

ENTRYPOINT ["hatch", "-e", "docker", "run", "proxyprotocol-server"]
CMD ["--help"]
