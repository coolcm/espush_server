FROM python:2.7

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app

RUN pip install --no-cache-dir  -i https://pypi.douban.com/simple -r requirements.txt && \
    rm -f requirements.txt

VOLUME /usr/src/app

EXPOSE 10081
EXPOSE 8000

