# encoding:utf-8
from __future__ import unicode_literals

import pytz
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import hashlib
import os
import datetime
from django.conf import settings


def md5(x):
    return hashlib.md5(x.lower()).hexdigest()

# Create your models here.


class MyUserManager(BaseUserManager):
    def create_user(self, email, password, stat):
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=MyUserManager.normalize_email(email),
            last_login=datetime.datetime.now(),
            stat=stat,
        )

        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, stat):
        if not email:
            raise ValueError('Users must have an email address')

        user = self.create_user(email,
                                password=password,
                                stat='OK')
        user.is_admin = True
        user.save()
        return user


class User(AbstractBaseUser):
    ch_stat = (('OK', '有效'), ('DELETED', '已删除'), ('LOCKED', '已锁定'))
    email = models.EmailField('邮箱', unique=True, db_index=True)
    is_admin = models.BooleanField('管理员', default=False)
    create_time = models.DateTimeField('产生日期时间', null=True, blank=True, auto_now_add=True)
    stat = models.CharField('状态', max_length=16, choices=ch_stat)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['stat', ]
    objects = MyUserManager()

    def __unicode__(self):
        return self.email

    def gravatar_url(self):
        if settings.LOCAL_TEST:
            urlhost = "https://espush.cn"
        else:
            urlhost = ""
        baseurl = urlhost + '/avatar/'
        return baseurl + md5(self.email) + '/'

    @property
    def is_staff(self):
        return self.is_admin

    @property
    def app_count(self):
        return self.app_set.filter(stat='OK').count()

    def has_module_perms(self, app_label):
        return self.is_admin

    def get_full_name(self):
        return self.email

    def get_short_name(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    class Meta:
        db_table = 't_user'
        verbose_name = '用户'


class App(models.Model):
    ch_stat = (('OK', '有效'), ('DELETED', '已删除'))
    app_name = models.CharField(max_length=32)
    secret_key = models.CharField(max_length=40)
    user = models.ForeignKey(User)
    single_mode = models.IntegerField('单设备模式', null=True, blank=True)
    create_time = models.DateTimeField('产生日期时间', null=True, blank=True, auto_now_add=True)
    stat = models.CharField('状态', max_length=16, choices=ch_stat)

    def __unicode__(self):
        return self.app_name

    class Meta:
        db_table = 't_app'
        verbose_name = 'app'


class Device(models.Model):
    ch_stat = (('OK', '有效'), )
    chip = models.CharField('设备芯片号', max_length=16)
    app = models.ForeignKey(App, null=True, blank=True)
    name = models.CharField('设备名称', max_length=32, null=True, blank=True)
    create_time = models.DateTimeField('产生日期时间', null=True, blank=True, auto_now_add=True)
    stat = models.CharField('状态', max_length=16, choices=ch_stat)

    def __unicode__(self):
        return self.chip

    class Meta:
        db_table = 't_device'
        verbose_name = '设备'


class Message(models.Model):
    ch_stat = (('OK', '有效'), ('DELETED', '已发送'))
    ch_msgtype = (('UPLOAD', '上传消息'),
                  ('PUSH_DEV', '推送消息'),
                  ('PUSH_APP', '群推消息'))
    ch_category = (('AT_CMD', 'AT指令'), ('LUA', 'Lua指令'), ('MSG', '普通消息'))
    app = models.ForeignKey(App, null=True, blank=True)
    dev = models.ForeignKey(Device, null=True, blank=True)
    msgtype = models.CharField('消息类别', max_length=8, choices=ch_msgtype)
    category = models.CharField('类别', max_length=8, choices=ch_category)
    create_time = models.DateTimeField('产生时间')
    recv_time = models.DateTimeField('接收时间', null=True, blank=True)
    msg = models.BinaryField('消息内容')
    user = models.ForeignKey(User, null=True, blank=True)
    stat = models.CharField('状态', max_length=16, choices=ch_stat)

    def __unicode__(self):
        return str(self.id)

    @property
    def msg_preview(self):
        return self.msg[:10].decode('gbk')

    class Meta:
        db_table = 't_message'
        verbose_name = '指令'


class UPLOAD_MSG(models.Model):
    ch_stat = (('VALID', '有效'), ('INVALID', '无效'))
    dev = models.ForeignKey(Device, null=True, blank=True)
    app = models.ForeignKey(App, null=True, blank=True)
    tag = models.CharField('标签', max_length=32, null=True, blank=True)
    body = models.BinaryField('消息内容')
    create_time = models.DateTimeField('创建时间')
    recv_time = models.DateTimeField('接收到时间')
    stat = models.CharField('状态', choices=ch_stat, max_length=16)

    @property
    def msg_preview(self):
        return self.body[:10].decode('gbk')

    @property
    def recv_time_without_timezone(self):
        return self.recv_time.astimezone(pytz.timezone(settings.TIME_ZONE))

    def __unicode__(self):
        return str(self.id)

    class Meta:
        db_table = 't_upload_msg'
        verbose_name = '设备上传的数据'


class TimerTaskRule(models.Model):
    ch_category = (('ONCE', '指定日期时间'),
                   ('INTERVAL', '定时循环'),
                   ('CRON_DAY', '每日定时'),
                   ('CRONTAB', 'CRONTAB'))
    ch_stat = (('INVALID', '未生效'), ('VALID', '有效'), ('DELETED', '已删除'))
    name = models.CharField('任务名称', max_length=32)
    taskid = models.CharField('任务编号', max_length=32)
    crontype = models.CharField('定时方式', max_length=16, choices=ch_category)
    cronval = models.CharField('执行周期', max_length=32)
    app = models.ForeignKey(App)
    pin = models.IntegerField('GPIO PIN')
    edge = models.IntegerField('GPIO EDGE')
    create_time = models.DateTimeField('创建时间', auto_now=True)
    begin_date = models.DateTimeField('开始日期', auto_now=True)
    end_date = models.DateTimeField('结束日期', null=True, blank=True)
    user = models.ForeignKey(User)
    stat = models.CharField('记录状态', max_length=16, choices=ch_stat)

    def __unicode__(self):
        return self.taskid

    class Meta:
        db_table = 't_timetaskrule'
        verbose_name = '定时任务'


def rom_checksum_md5(x):
    return hashlib.md5(x).hexdigest()


class EspRom(models.Model):
    ch_stat = (('VALID', '有效'), ('DELETED', '已删除'))
    name = models.CharField('固件类型', max_length=32)
    realname = models.CharField('显示名称', max_length=64, null=True, blank=True)
    version = models.CharField('固件版本', max_length=16)
    rom = models.CharField('文件路径', max_length=128)
    user1 = models.CharField('user1.bin', max_length=128, null=True, blank=True)
    user2 = models.CharField('user2.bin', max_length=128, null=True, blank=True)
    upload_time = models.DateTimeField('上传日期')
    stat = models.CharField('固件状态', max_length=10, choices=ch_stat)

    @property
    def md5sum(self):
        outpath = settings.ROMS_UPLOAD_DIR
        filename = os.path.join(outpath, self.rom)
        with open(filename, 'rb') as fin:
            return rom_checksum_md5(fin.read())

    def __unicode__(self):
        return str(self.id) + self.name

    class Meta:
        db_table = 't_esprom'
        verbose_name = '固件'


class UserAuthToken(models.Model):
    '''TOKEN base64(md5(uuid))'''
    ch_stat = (('VALID', '有效'), )
    user = models.ForeignKey(User)
    token = models.CharField('TOKEN', max_length=128)
    create_time = models.DateTimeField('创建时间')
    expire_time = models.DateTimeField('过期时间')
    stat = models.CharField('状态', max_length=16)

    def __unicode__(self):
        return self.token

    class Meta:
        db_table = 't_userauth_token'
        verbose_name = 'App用户'
