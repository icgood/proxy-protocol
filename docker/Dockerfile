FROM python:3.8-alpine

RUN pip install -U pip wheel setuptools typing-extensions

ARG install_arg="proxy-protocol"
RUN apk --update add --virtual build-dependencies python3-dev build-base \
  && pip install ${install_arg} \
  && apk del build-dependencies

ENTRYPOINT ["proxyprotocol-server"]
