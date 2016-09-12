# encoding: utf-8

from __future__ import unicode_literals

import json
import logging

import redis
import requests

from django.conf import settings

from contrib.exceptions import WechatAPICallError
from webv2.models import App, Device

logger = logging.getLogger('espush')



def reqjson(func):
    '''Hack for Anuglar'''
    def _wrapper(request, *args, **kwargs):
        '''直接把request.body使用json进行反序列化'''
        if isinstance(request.body, bytes):
            body = request.body.decode('utf-8')
        else:
            body = request.body
        try:
            request.reqjson = json.loads(body)
        except ValueError:
            request.reqjson = {}
        return func(request, *args, **kwargs)
    return _wrapper


ESPUSH_VERTYPE_MAP = {
    0: 'UNKNOWN',
    1: 'AT',
    2: 'NODEMCU',
    3: 'SDK',
    4: 'OTHER',
    5: 'AT_PLUS'
}


def has_dev_permission(chipid, appobj=None, appid=None):
    if appobj is None and appid is None:
        raise AttributeError('参数错误, APPID与APPOBJ必居其一')
    if appid is not None and appobj is None:
        try:
            db_appobj = App.objects.get(id=appid)
        except App.DoesNotExist as _:
            return None
    elif appid is None and appobj is not None:
        db_appobj = appobj
    else:
        raise AttributeError('参数错误，APPID与APPOBJ只能填一个')
    devs = Device.objects.filter(chip=chipid, app=db_appobj, stat='OK')
    if not devs:
        return None
    return chipid


def redis_client():
    return redis.Redis(settings.REDIS_HOST)


def wechat_userinfo_batchget(openid_list):
    if not openid_list:
        return {}
    redis_obj = redis_client()
    access_token = redis_obj.get('WECHAT_ESPUSH_ACCESS_TOKEN')
    if not access_token:
        raise Exception('ACCESS_TOKEN 未配置，错误！')
    url = 'https://api.weixin.qq.com/cgi-bin/user/info/batchget?access_token=%s' % access_token
    reqbody = {
        "user_list": [{"openid": openid} for openid in openid_list]
    }
    try:
        rsp = requests.post(url, data=json.dumps(reqbody), timeout=10)
    except requests.Timeout:
        raise WechatAPICallError('微信接口调用超时')
    except requests.RequestException:
        raise WechatAPICallError('微信接口调用失败!')
    result = rsp.json()
    if 'user_info_list' not in result:
        raise WechatAPICallError('微信接口调用成功，但返回结果无 user_info_list 字段')
    userInfoList = result.get('user_info_list')
    userInfoMap = {}
    for userInfo in userInfoList:
        if 'openid' not in userInfo:
            continue
        openid = userInfo.get('openid')
        userInfoMap[openid] = userInfo
    return userInfoMap
