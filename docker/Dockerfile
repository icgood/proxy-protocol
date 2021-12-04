FROM python:3.10-alpine

WORKDIR /src
COPY . .

RUN pip install -U pip wheel setuptools typing-extensions

RUN apk --update add --virtual build-dependencies python3-dev build-base \
  && pip install -r requirements-all.txt \
  && apk del build-dependencies

ENTRYPOINT ["proxyprotocol-server"]
CMD ["--help"]
