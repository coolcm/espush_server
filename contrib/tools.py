# encoding: utf-8

from __future__ import unicode_literals


import os
import logging

import requests
from django.http import HttpResponse
from django.conf import settings

from contrib.exceptions import GatewayTimeoutError, GatewayCallError
from webv2.models import App, Device

logger = logging.getLogger('espush')


def make_down_available_rsp(filepath, filename):
    types = 'application/octet-stream'
    with open(os.path.join(filepath, filename), 'rb') as fin:
        rsp = HttpResponse(fin.read(), content_type=types)
        rsp['Content-Disposition'] = 'filename=%s' % filename
        return rsp


def appkey_from_appid(appid):
    return App.objects.get(id=appid).secret_key


def get_user_online_jsondev(appid_list):
    url = 'http://%s/online_dev?' % settings.SOCK_SERVER
    for appid in appid_list:
        url += '&app=%d' % appid
    try:
        rsp = requests.get(url, timeout=1)
        logger.info(rsp.content)
    except requests.Timeout as _:
        logger.warn('获得用户在线设备时，服务端请求超时')
        raise GatewayTimeoutError("网关服务器超时")
    if rsp.status_code != 200:
        logger.warn('获得用户在线设备时，服务端返回错误, [%d]', rsp.status_code)
        raise GatewayCallError("网关服务器调用错误")
    return rsp.json()


def get_user_online_devices(appid_list):
    online_devs_for_app = get_user_online_jsondev(appid_list)
    for devobj in online_devs_for_app:
        appid = devobj.get('appid')
        if not appid:
            continue
        app_db = App.objects.get(id=appid)
        devobj['appname'] = app_db.app_name
        devobj['appobj'] = app_db
        try:
            dev_dbobj = Device.objects.get(chip=devobj.get('devid'),
                                           app=app_db)
        except Device.DoesNotExist as _:
            continue
        devobj['devname'] = dev_dbobj.name
    return online_devs_for_app
