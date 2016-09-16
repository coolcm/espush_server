FROM python:2.7

MAINTAINER admin@espush.cn

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app

RUN pip install --no-cache-dir  -i https://pypi.douban.com/simple -r requirements.txt && \
    rm -f requirements.txt

ADD . /usr/src/app
RUN chmod +x /usr/src/app/entrypoint.py

EXPOSE 10081
EXPOSE 8000

ENTRYPOINT ["/usr/src/app/entrypoint.py"]
