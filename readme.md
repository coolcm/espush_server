#tutorial

- 准备工作
docker pull espushcloud/espush

docker pull postgres:9.5
docker pull python:2.7
git clone https://github.com/pushatccgzs/espush.git

- 系统初始化
cd 
docker build 

- 访问


- 初始化数据库
docker run -v `pwd`/data:/var/lib/postgresql/data --name espush\_db -e POSTGRES\_PASSWORD=123456 -d postgres:9.5
docker logs espush\_db

    PostgreSQL init process complete; ready for start up.
    LOG:  database system was shut down at 2016-09-12 15:45:15 UTC
    LOG:  MultiXact member wraparound protections are now enabled
    LOG:  database system is ready to accept connections
    LOG:  autovacuum launcher started
    

docker run -i -t --link espush_db:espush_db postgres:9.5 psql -h espush_db -U postgres
输入密码后新建用户与数据库环境
create user espush createdb ;
alter user espush with password '123456';
\c template1 espush
create database espush;

cd espush
docker run --name dbinit -i -t --link espush_db:espush_db -v `pwd`:/usr/src/app espush/espush /bin/bash

编辑espush.ini，为刚刚配置的数据库信息

python manage.py makemigrations webv2
python manage.py makemigrations weixin
python manage.py migrate


root@a653d9ee1837:/usr/src/app# python manage.py migrate
Operations to perform:
  Synchronize unmigrated apps: staticfiles, messages
  Apply all migrations: webv2, admin, sessions, auth, weixin, contenttypes
Synchronizing apps without migrations:
  Creating tables...
    Running deferred SQL...
  Installing custom SQL...
Running migrations:
  Rendering model states... DONE
  Applying webv2.0001_initial... OK
  Applying contenttypes.0001_initial... OK
  Applying admin.0001_initial... OK
  Applying contenttypes.0002_remove_content_type_name... OK
  Applying auth.0001_initial... OK
  Applying auth.0002_alter_permission_name_max_length... OK
  Applying auth.0003_alter_user_email_max_length... OK
  Applying auth.0004_alter_user_username_opts... OK
  Applying auth.0005_alter_user_last_login_null... OK
  Applying auth.0006_require_contenttypes_0002... OK
  Applying sessions.0001_initial... OK
  Applying weixin.0001_initial... OK


- 启动系统
docker run --name espush -i -t -p 10081:10081 -p 8000:8000 --link espush_db:espush_db -v `pwd`:/usr/src/app espush/espush /bin/bash

python manage.py runserver 0.0.0.0:8000 &
cd gateway
python router.py &
python svc_espush.py &

需要增加系统初始化脚本， 用作初始化数据库（并自动修改配置文件）、启动进程



docker run -i -t --link db:db -e POSTGRES_PASSWORD=123456 espush/espush init
