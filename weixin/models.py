# encoding: utf-8

from __future__ import unicode_literals
from __future__ import print_function


from django.db import models
from django.conf import settings
# Create your models here.


class WechatUser(models.Model):
    ch_stat = (('VALID', '有效'), ('UNFOLLOWED', '已删除'))
    openid = models.CharField('微信openid', max_length=128)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, blank=True, null=True)
    create_time = models.DateTimeField('产生日期时间', null=True, blank=True, auto_now_add=True)
    stat = models.CharField('关注状态', max_length=16)

    def __unicode__(self):
        return self.openid

    class Meta:
        db_table = 't_wechat_user'
        verbose_name = '微信用户'


class WechatToken(models.Model):
    '''TOKEN base64(md5(uuid))'''
    ch_stat = (('VALID', '有效'), )
    wechat_user = models.ForeignKey(WechatUser)
    token = models.CharField('TOKEN', max_length=128)
    create_time = models.DateTimeField('创建时间')
    expire_time = models.DateTimeField('过期时间')
    stat = models.CharField('状态', max_length=16)

    def __unicode__(self):
        return self.token

    class Meta:
        db_table = 't_wechat_token'
        verbose_name = '微信用户'


class WechatFeedback(models.Model):
    '''微信可以直接反馈'''
    wechat_user = models.ForeignKey(WechatUser)
    content = models.TextField('feedback')
    create_time = models.DateTimeField('产生日期时间', null=True, blank=True, auto_now_add=True)

    def __unicode__(self):
        return str(self.id)

    class Meta:
        db_table = 't_wechat_feedback'
        verbose_name = '微信反馈'
