#tutorial

##前置条件

准备Ubuntu 14.04 或以上，CentOS 7 或以上的Linux系统，要求能正常使用Docker即可！分别使用
```
# Ubuntu
apt-get install docker
/etc/init.d/docker start
```

```
# CentOS
yum install docker
systemctl start docker
```

安装docker。另外，可能需要关闭CentOS，尝试使用 `setenforce 0` 关闭SeLinux以避免奇奇怪怪的一些问题。


##准备工作

```
docker pull postgres:9.5
docker pull espushcloud/espush
```

##系统初始化

新建用于数据库的目录，并启动数据库：

```
# 修改POSTGRES_PASSWORD其后的密码，并记住
docker run -v `pwd`/data:/var/lib/postgresql/data --name db -e POSTGRES_PASSWORD=123456 -d postgres:9.5
docker logs db
#下面应该是你需要看到的postgres输出日志：
...... 省略部分内容
server stopped
PostgreSQL init process complete; ready for start up.
LOG:  database system was shut down at 2016-09-16 07:02:36 UTC
LOG:  MultiXact member wraparound protections are now enabled
LOG:  database system is ready to accept connections
LOG:  autovacuum launcher started
```

数据库即告启动完成，接下来需要初始化数据库表结构，执行命令：
```
# 同样留意修改对应的密码，为上面初始化的密码。指定运行参数为init；
docker run -i -t --link db:db -e POSTGRES_PASSWORD=123456 espushcloud/server:latest init
# Database Username [default: espush]> 提示输入数据库用户名、密码、数据库实例名，管理员邮箱、密码，完成后提示如下：
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
```

##启动服务器与Web
```
docker run --name espush -d -p 10081:10081 -p 8000:8000 --link db:db espushcloud/server
docker logs espush
```

完！

##总结
```
yum install docker # apt-get install docker
systemctl start docker
docker pull postgres:9.5
docker pull espushcloud/server:latest
docker run -v `pwd`/data:/var/lib/postgresql/data --name db -e POSTGRES_PASSWORD=123456 -d postgres:9.5
docker run -i -t --link db:db -e POSTGRES_PASSWORD=123456 espushcloud/server:latest init
docker run --name espush -d -p 10081:10081 -p 8000:8000 --link db:db espushcloud/server
```


