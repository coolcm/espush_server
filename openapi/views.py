# encoding: utf-8
from __future__ import unicode_literals

import os
import struct
import time
import logging
import hashlib
import uuid
import base64
import datetime
import binascii

import requests

from django.conf import settings
from django.contrib.auth import authenticate
from django.http.response import JsonResponse, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt

from contrib.utils import reqjson, ESPUSH_VERTYPE_MAP, has_dev_permission
from contrib.exceptions import GatewayCallError, GatewayTimeoutError
from webv2.models import App, Device, Message, UPLOAD_MSG, EspRom, UserAuthToken
from contrib.tools import make_down_available_rsp, appkey_from_appid, get_user_online_devices

# Create your views here.

logger = logging.getLogger('espush')


def md5(s):
    return hashlib.md5(s).hexdigest().lower()


def to_int(s):
    try:
        return int(s)
    except ValueError as _:
        return None


class HttpResponseAuthorizeFailed(HttpResponse):
    status_code = 401


r'''
公共参数：
timestamp
appid
sign

其中sign的计算方法如下：

请求的方法 小写
其他参数使用KV形式，不包括sign，并将所有转换为小写字母表示，未做urlencode，按key的降序排列，如key3=v3&key2=v2&key1=v1
APPKEY

如：
postappid=15104&timestamp=1433606430854728a8061611e5925a002288fc6d2b
sign=b3a00d0e9e8aa7b56d82693345dc3471

gettimestamp=1433814203&appid=123425b28f0ffb9711e4a96d446d579b49a1

timestamp=1433814203&appid=1234&sign=9f0b613de12d5bb0451c556900a39559

做md5，为sign的值
'''


def sign_check(fn):
    def _wrapper(request, *args, **kwargs):
        method = request.method
        appid_raw = request.REQUEST.get('appid')
        timestamp = request.REQUEST.get('timestamp')
        sign = request.REQUEST.get('sign')
        if not appid_raw:
            logger.warn('设备类别APP错误, 不得为空')
            return JsonResponse({'msg': '设备类别APP错误'}, status=400)
        appid = to_int(appid_raw)
        if not appid:
            logger.warn('设备类别APP必须为整数')
            return JsonResponse({'msg': '设备类别APP格式错误'}, status=400)
        if not timestamp:
            logger.warn('时间戳错误, 不得为空')
            return JsonResponse({'msg': '时间戳参数错误'}, status=400)
        stamp = to_int(timestamp)
        if not stamp:
            logger.warn('时间戳必须为整数')
            return JsonResponse({'msg': '时间戳必须为整数'}, status=400)
        local_timestamp = int(time.time())
        if local_timestamp - stamp >= 3600:
            logger.warn('时间间隔大于一小时')
            return JsonResponse({'msg': '时间间隔大于一小时'}, status=400)
        if not sign:
            logger.warn('签名错误, 不得为空')
            return JsonResponse({'msg': '签名错误'}, status=400)
        argsobj = dict(request.REQUEST)
        del argsobj['sign']
        args_str = '&'.join(['%s=%s' % (el, argsobj[el])
                             for el in reversed(sorted(argsobj))])
        args_str = args_str.lower()
        try:
            db_app = App.objects.get(id=appid_raw, stat='OK')
        except RuntimeError as _:
            logger.warn('未找到适合的设备类别APP [%s]', appid_raw)
            return JsonResponse({'msg': '设备类别不存在'}, status=400)
        except App.DoesNotExist as _:
            logger.warn('未找到适合的设备类别APP [%s]', appid_raw)
            return JsonResponse({'msg': '设备类别不存在'}, status=400)
        appkey = db_app.secret_key
        hrs = '%s%s%s' % (method, args_str, appkey)
        hrs = hrs.lower()
        hrs = hrs.encode('utf-8')
        hashstr = md5(hrs)
        logger.info('签名 sign: [%s], hash: [%s], [%s]' % (sign, hashstr, hrs.decode('utf-8')))
        if sign != hashstr:
            logger.warn('签名不正确')
            return JsonResponse({'msg': '签名不正确'}, status=400)
        request.cur_app = db_app
        request.cur_user = db_app.user
        return fn(request, *args, **kwargs)
    return _wrapper


def sign_user_check(fn):
    def _wrapper(request, *args, **kwargs):
        now = datetime.datetime.now()
        token = request.META.get('HTTP_TOKEN')
        if not token:
            return HttpResponseBadRequest('Need Authorize.')
        try:
            tokenobj = UserAuthToken.objects.get(token=token,
                                                 stat='VALID',
                                                 expire_time__gt=now)
        except UserAuthToken.DoesNotExist as _:
            return HttpResponseForbidden('ERROR Authorize.')
        request.user = tokenobj.user
        request.tokenobj = tokenobj
        return fn(request, *args, **kwargs)
    return _wrapper


'''
@cb1
def fb(args):
    pass


fb = cb1(fb)(args)
'''


@sign_check
def index(request):
    pass


@sign_check
def all_devices_list(request):
    devs = Device.objects.filter(app=request.cur_app).filter(stat='OK')
    retarr = [el.chip for el in devs]
    return JsonResponse(retarr, safe=False)


@sign_check
def online_devices_list(request):
    url = 'http://%s/online_dev?app=%d'\
        % (settings.SOCK_SERVER, request.cur_app.id)
    try:
        rsp = requests.get(url, timeout=5)
    except requests.Timeout as _:
        return JsonResponse({'msg': '服务器网关丢失连接'})
    arr = rsp.json()
    for el in arr:
        chip = el.get('devid')
        if not chip:
            continue
        try:
            dev_dbobj = Device.objects.get(chip=chip, app=request.cur_app)
        except Device.DoesNotExist as _:
            continue
        el['name'] = dev_dbobj.name
    return JsonResponse(arr, safe=False)


@csrf_exempt
@sign_check
def dev_push_msg(request):
    _chipid = request.REQUEST.get('devid')
    chipid = to_int(_chipid)
    if not chipid:
        logger.warn('设备芯片号需为整数')
        return JsonResponse({'msg': "设备芯片号需为整数"}, status=400)
    msg = request.REQUEST.get('message')
    msg = msg.encode("GBK")
    msgformat = request.REQUEST.get('format')
    if not format:
        logger.info(u'未选择指令类型，默认为文本')
        msgformat = u'MSG'
    if msgformat not in [u'MSG', u'HEX', u'AT', u'LUA', u'LUA_HEX', u'B64']:
        logger.info(u'指令类型错误')
        return JsonResponse({"msg": u"指令类型错误"}, status=400)
    if msgformat == u'HEX':
        if len(msg) % 2:
            logger.warn(u'十六进制原始数值长度需为偶数')
            return JsonResponse({"msg": u"十六进制原始数值长度需为偶数"}, status=400)
        try:
            msg = binascii.a2b_hex(msg)
        except Exception as _:
            logger.warn(u'十六进制数值错误')
            return JsonResponse({"msg": u"无法解析十六进制值"}, status=400)
    if msgformat == 'B64':
        msg = base64.b64decode(msg)
    if msgformat == u'AT':
        if len(msg) > 64 and ('\r' in msg or '\n' in msg):
            logger.info(u'AT指令长度不得超过64字节，且不得换行')
            return JsonResponse({"msg": u"AT指令长度不得超过64字节，且不得换行"}, status=400)
    if msgformat == u'LUA_HEX':
        msg = base64.b64decode(msg)
    if msgformat == u'AT':
        msgtype = 0x14
        msg += '\r\n'
    elif msgformat in [u'MSG', u'HEX', u'B64']:
        msgtype = 0x04
    elif msgformat == u'LUA':
        msgtype = 0x16
    elif msgformat == u'LUA_HEX':
        msgtype = 0x16
    # 判断是否有权限操作此设备
    if not has_dev_permission(chipid, appobj=request.cur_app):
        logger.warn(u'无操作权限 [%d], [%d]', chipid, request.cur_app.id)
        return JsonResponse({"msg": "无设备对应操作权限！"},status=400)
    url = 'http://%s/_push_data?dev=%d&msgtype=%d'\
        % (settings.SOCK_SERVER, chipid, msgtype)
    try:
        rsp = requests.post(url, data=msg, timeout=50)
        if rsp.status_code != 200:
            logger.warn(u'网关返回错误，数据可能推送失败')
            return JsonResponse({'msg': "网关返回错误"}, status=504)
    except requests.Timeout as _:
        logger.error(u'网关请求超时')
        return JsonResponse({'msg': "网关请求超时"}, status=504)
    except IOError as _:
        logger.error(u'请求失败')
        return JsonResponse({'msg': "请求网关失败"}, status=504)
    # 新建数据库记录 以供浏览
    try:
        dev_db = Device.objects.get(chip=chipid, app=request.cur_app)
    except Device.DoesNotExist as _:
        dev_db = Device(chip=chipid, app=request.cur_app, stat="OK")
        dev_db.save()
    except Device.MultipleObjectsReturned as _:
        logger.error('服务器逻辑错误，存在相同记录 [%d] [%d]',
                     chipid, request.cur_app.id)
        return JsonResponse({'msg': "网关返回错误"}, status=504)
    if isinstance(msg, unicode):
        msg = msg.encode('utf-8')
    record = Message(dev=dev_db,
                     app=request.cur_app,
                     msgtype='PUSH_DEV',
                     category='MSG',
                     create_time=datetime.datetime.now(),
                     msg=msg,
                     user=request.cur_user,
                     stat="OK")
    record.save()
    return JsonResponse({"msg": "OK"})


@sign_check
def dev_push_ota(request, chipid):
    return JsonResponse({"msg": "OK"})


def dev_userbin(requeset, chipid):
    return JsonResponse({"msg": "OK"})


@sign_check
def dev_is_alive(request, chipid):
    return JsonResponse({"msg": "OK"})


@sign_check
def up_messages(request):
    fmt_full = '%Y-%m-%d %H:%M:%S'
    msgs = UPLOAD_MSG.objects.filter(app=request.cur_app)
    retobj = [{
               'id': msg.id,
               'app': msg.app.app_name,
               'dev': msg.dev.chip if msg.dev is not None else '',
               'body': str(msg.body),
               'create_time': msg.create_time.strftime(fmt_full)
               }
              for msg in msgs]
    retobj.sort(cmp=lambda x,y: -1 * cmp(deserialize_datetime(x['create_time'], fmt_full), deserialize_datetime(y['create_time'], fmt_full)))
    return JsonResponse(retobj, safe=False)


@sign_check
def up_dev_messages(request, _chipid):
    fmt_full = '%Y-%m-%d %H:%M:%S'
    dev_db_s = Device.objects.filter(chip=_chipid)
    if not dev_db_s:
        return JsonResponse({"MSG": "devices not found"}, status=404)
    dev_db = dev_db_s[0]
    msgs = UPLOAD_MSG.objects.filter(app=request.cur_app, dev=dev_db).order_by('-create_time')
    retobj = [{
               'id': msg.id,
               'app': msg.app.app_name,
               'body': str(msg.body),
               'dev': _chipid,
               'create_time': msg.create_time.strftime(fmt_full)
               }
              for msg in msgs]
    retobj.sort(cmp=lambda x,y: -1 * cmp(deserialize_datetime(x['create_time'], fmt_full), deserialize_datetime(y['create_time'], fmt_full)))
    return JsonResponse(retobj, safe=False)


@sign_check
def push_messages(request):
    fmt_full = '%Y-%m-%d %H:%M:%S'
    msgs = Message.objects.filter(msgtype__in=['PUSH_DEV', 'PUSH_APP'],
                                  app=request.cur_app)
    retobj = [{
               'id': msg.id,
               'dev': msg.dev.chip if msg.dev is not None else '',
               'body': str(msg.msg),
               'msgtype': msg.get_msgtype_display(),
               'create_time': msg.create_time.strftime(fmt_full)
               }
              for msg in msgs]
    retobj.sort(cmp=lambda x,y: -1 * cmp(deserialize_datetime(x['create_time'], fmt_full), deserialize_datetime(y['create_time'], fmt_full)))
    return JsonResponse(retobj, safe=False)


@sign_check
def dev_push_messages(request, _chipid):
    fmt_full = '%Y-%m-%d %H:%M:%S'
    dev_db_s = Device.objects.filter(chip=_chipid)
    if not dev_db_s:
        return JsonResponse({"MSG": "devices not found"}, status=404)
    dev_db = dev_db_s[0]
    msgs = Message.objects.filter(msgtype='PUSH_DEV').filter(dev=dev_db).order_by('-create_time')
    retarr = []
    for msg in msgs:
        b1 = bytearray(msg.msg)
        b1 = b1.strip()
        cur_msg = {
           'id': str(msg.id),
           'body': ''.join([hex(el)[2:] for el in b1]),
           'msgtype': msg.get_msgtype_display(),
           'dev': _chipid,
           'create_time': msg.create_time.strftime(fmt_full)
           }
        retarr.append(cur_msg)
    return JsonResponse(retarr, safe=False)


@csrf_exempt
@sign_check
def app_push_msg(request):
    msg = request.REQUEST.get('message', '')
    # 检查MSG传值
    if not msg:
        logger.warn('推送内容不得为空')
        return JsonResponse({'msg': "推送内容不得为空"}, status=403)
    msg = msg.encode('GBK')
    msgformat = request.REQUEST.get('format')
    if not format:
        logger.info(u'未选择指令类型，默认为文本')
        msgformat = u'MSG'
    if msgformat not in [u'MSG', u'HEX', u'AT', u'LUA']:
        logger.info(u'指令类型错误')
        return JsonResponse({"msg": u"指令类型错误"})
    if msgformat == u'HEX':
        if len(msg) % 2:
            logger.warn(u'十六进制原始数值长度需为偶数')
            return JsonResponse({"msg": u"十六进制原始数值长度需为偶数"})
        try:
            msg = binascii.a2b_hex(msg)
        except Exception as _:
            logger.warn(u'十六进制数值错误')
            return JsonResponse({"msg": u"无法解析十六进制值"})
    if msgformat == u'AT':
        if len(msg) > 64 and ('\r' in msg or '\n' in msg):
            logger.info(u'AT指令长度不得超过64字节，且不得换行')
            return JsonResponse({"MSG": u"AT指令长度不得超过64字节，且不得换行"})
    if msgformat == u'AT':
        msgtype = 0x14
        msg += '\r\n'
    elif msgformat in [u'MSG', u'HEX']:
        msgtype = 0x04
    elif msgformat == u'LUA':
        msgtype = 0x16
    url = 'http://%s/push_app?app=%d&msgtype=%d' % (settings.SOCK_SERVER, request.cur_app.id, msgtype)
    # url = 'http://%s/_push_data?dev=%d&msgtype=%d' % (settings.SOCK_SERVER, chipid, msgtype)
    try:
        rsp = requests.post(url, data=msg, timeout=5)
        if rsp.status_code != 200:
            logger.warn('服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn('服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    if isinstance(msg, unicode):
        msg = msg.encode('utf-8')
    record = Message(app=request.cur_app,
                     msgtype='PUSH_APP',
                     category='MSG',
                     create_time=datetime.datetime.now(),
                     msg=msg,
                     user=request.cur_user,
                     stat="OK")
    record.save()
    return JsonResponse({'msg': "sucess"})


@sign_check
def appinfo(request):
    appinfo = {'name': request.cur_app.app_name}
    url = "http://%s/online_dev?app=%d" % (settings.SOCK_SERVER, request.cur_app.id)
    try:
        rsp = requests.get(url, timeout=5)
        if rsp.status_code != 200:
            logger.warn('服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn('服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    ol_devs = rsp.json()
    for dev in ol_devs:
        chipid = dev.get('devid')
        if not chipid:
            continue
        dev_db_s = Device.objects.filter(chip=str(chipid))
        if not dev_db_s:
            continue
        dev_db = dev_db_s[0]
        dev_name = dev_db.name
        dev['name'] = dev_name if dev_name else chipid
    appinfo['online'] = ol_devs
    return JsonResponse(appinfo)


def deserialize_datetime(s, fmt):
    try:
        return datetime.datetime.strptime(s, fmt)
    except Exception as _:
        return None


@sign_check
def sync(request, begin_point, end_point):
    fmt = '%Y%m%d'
    fmt_full = '%Y-%m-%d %H:%M:%S'
    begin = deserialize_datetime(begin_point, fmt)
    end = deserialize_datetime(end_point, fmt)
    if not begin or not end:
        logger.warn('时间日期格式错误，只允许日期型')
        return JsonResponse({'msg': 'date format error'}, status=400)
    records = UPLOAD_MSG.objects.filter(app=request.cur_app, create_time__range=[begin, end])
    retarr = [{'id': el.id,
               'chipid': el.dev.chip,
               'app': el.app.app_name,
               'create_time': el.create_time.strftime(fmt_full),
               'recv_time': el.recv_time.strftime(fmt_full),
               'body': str(el.body)
               } for el in records]
    retarr.sort(cmp=lambda x,y: -1 * cmp(deserialize_datetime(x['create_time'], fmt_full), deserialize_datetime(y['create_time'], fmt_full)))
    return JsonResponse(retarr, safe=False)


@sign_check
def rt_status(request, chip):
    func_key = request.GET.get("key")
    chipid = to_int(chip)
    if not func_key:
        logger.warn('key值为空，无法查询实时状态')
        return JsonResponse({"msg": "key值为空"}, status=400)
    if not has_dev_permission(chipid, appobj=request.cur_app):
        logger.warn(u'无操作权限 [%d], [%d]', chipid, request.cur_app.id)
        return JsonResponse({"msg": "无设备对应操作权限！"},status=400)
    url = 'http://%s/_push_data?dev=%d&msgtype=%d' % (settings.SOCK_SERVER, chipid, 0x1C)
    try:
        rsp = requests.post(url, data=func_key, timeout=5)
        if rsp.status_code != 200:
            logger.warn('服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn('服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    # return JsonResponse({"result": rsp.content[11:]})
    return HttpResponse(rsp.content[11:])


@sign_check
def gpio_status(request, chip):
    chipid = to_int(chip)
    if not has_dev_permission(chipid, appobj=request.cur_app):
        logger.warn(u'无操作权限 [%d], [%d]', chipid, request.cur_app.id)
        return JsonResponse({"msg": "无设备对应操作权限！"},status=400)
    url = 'http://%s/_push_data?dev=%d&msgtype=%d' % (settings.SOCK_SERVER, chipid, 0x20)
    try:
        rsp = requests.post(url, timeout=5)
        if rsp.status_code != 200:
            logger.warn('服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn('服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    return JsonResponse({"result": rsp.content[10:]})


@sign_check
def manual_refresh(request, chipid):
    chip = to_int(chipid)
    if not has_dev_permission(chip, appobj=request.cur_app):
        logger.warn(u'无操作权限 [%d], [%d]', chip, request.cur_app.id)
        return JsonResponse({"msg": "无设备对应操作权限！"},status=400)
    url = 'http://%s/dev_refresh?chipid=%d' % (settings.SOCK_SERVER, chip)
    # 发出网络请求, 推送数据
    try:
        rsp = requests.post(url, timeout=8)
        if rsp.status_code != 200:
            logger.warn(u'网关返回错误，接口调用失败')
            return JsonResponse({"msg": "网关返回错误"}, status=504)
    except requests.Timeout as _:
        logger.error(u'网关请求超时')
        return JsonResponse({"msg": "网关请求超时"}, status=504)
    except IOError as _:
        logger.error(u'请求失败')
        return JsonResponse({"msg": "网关请求失败"}, status=504)
    if rsp.content == 'offline':
        logger.info(u'设备 [%d] 已离线', chip)
        return JsonResponse({"status": "offline", "msg": "OK"})
    logger.info(u'设备 [%d] 在线', chip)
    return JsonResponse({"status": "online", "msg": "OK"})


@csrf_exempt
@sign_check
def set_gpio_edge(request, chip, pin, edge):
    if edge not in ['1', '0']:
        logger.warn('电平态只能为0 或 1')
        return JsonResponse({"msg": "电平态只能为0 或 1"})
    if not has_dev_permission(chip, appobj=request.cur_app):
        logger.warn(u'无操作权限 [%d], [%d]', to_int(chip), request.cur_app.id)
        return JsonResponse({"msg": "无设备对应操作权限！"},status=400)
    chipid = to_int(chip)
    url = 'http://%s/_push_data?dev=%d&msgtype=%d' % (settings.SOCK_SERVER, chipid, 0x1E)
    body = chr(int(pin)) + chr(int(edge))
    try:
        rsp = requests.post(url, data=body, timeout=5)
        if rsp.status_code != 200:
            logger.warn('服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn('服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    return JsonResponse({"result": rsp.content[10:]})


@csrf_exempt
@sign_check
def reboot_dev(request, _chip):
    chipid = to_int(_chip)
    if not has_dev_permission(chipid, appobj=request.cur_app):
        logger.warn(u'无操作权限 [%d], [%d]', chipid, request.cur_app.id)
        return JsonResponse({"msg": "无设备对应操作权限！"},status=400)
    url = 'http://%s/_push_data?dev=%d&msgtype=%d' % (settings.SOCK_SERVER, chipid, 0x12)
    try:
        rsp = requests.post(url, timeout=5)
        if rsp.status_code != 200:
            logger.warn('服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn('服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    return JsonResponse({"result": rsp.content[10:]})


@csrf_exempt
@sign_check
def notice_api_test(request):
    return HttpResponse("OK")


@sign_check
def whether_is_online(request, _chip):
    chipid = to_int(_chip)
    if not chipid:
        logger.warn('检测是否在线， CHIP参数必须为整形')
        return JsonResponse({"msg": "chipid arguments error."}, status=400)
    if not has_dev_permission(chipid, appobj=request.cur_app):
        logger.warn(u'无操作权限 [%d], [%d]', chipid, request.cur_app.id)
        return JsonResponse({"msg": "无设备对应操作权限！"},status=400)
    url = 'http://%s/all_online' % settings.SOCK_SERVER
    try:
        rsp = requests.get(url, timeout=5)
        if rsp.status_code != 200:
            logger.warn('服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn('服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    found = False
    for devobj in rsp.json():
        if 'chipid' in devobj and devobj['chipid'] == chipid:
            found = True
    return JsonResponse({
        "result" :"OK",
        "status": "online" if found else "offline"
    })


def romlist(request):
    '''
    id: 1,
    version: '0.10.1',
    name: 'NodeMCU',
    checksum: 'acc2322cd9bac2bee9b4cf720fd5b66f'
    :param request:
    :return:
    '''
    available_flash = ['AT', 'NodeMCU', 'AT_PLUS']
    result = []
    for romname in available_flash:
        roms = EspRom.objects.filter(stat='VALID', name=romname).order_by('-id')
        if not roms:
            continue
        result.append(roms[0])
    out = [{
        'id': romobj.id,
        'name': romobj.name,
        'version': romobj.version,
        'realname': romobj.realname,
        'checksum': romobj.md5sum
           } for romobj in result]
    return JsonResponse(out, safe=False)


def romfile(request, romid):
    outpath = settings.ROMS_UPLOAD_DIR
    try:
        romdbobj = EspRom.objects.get(id=romid, stat='VALID')
    except EspRom.DoesNotExist as _:
        return JsonResponse({'msg': '找不到指定的资源'}, status=404)
    return make_down_available_rsp(outpath, romdbobj.rom)


@csrf_exempt
@reqjson
def user_login(request):
    email = request.reqjson.get('email')
    password = request.reqjson.get('password')
    now = datetime.datetime.now()
    expire_time = datetime.datetime(9999, 9, 9, 9, 9, 9, 9)
    if not email or not password:
        return HttpResponseAuthorizeFailed('用户名或密码为空，认证失败！')
    password = hashlib.md5(password).hexdigest()
    userobj = authenticate(username=email, password=password)
    if not userobj:
        return HttpResponseAuthorizeFailed("用户名或密码错误，认证失败！")
    if userobj.stat != 'OK':
        return HttpResponseAuthorizeFailed('用户已过期或被锁定，请重新注册！')
    token_str = md5(uuid.uuid1().get_bytes())
    tokenobj = UserAuthToken(
        user=userobj,
        token=token_str,
        create_time=now,
        expire_time=expire_time,
        stat='VALID'
    )
    tokenobj.save()
    return JsonResponse({
        'email': email,
        'token': token_str,
        'expire': '9999-09-09 09:09:00'
    })


@sign_user_check
def user_online_devices(request):
    apps = App.objects.filter(user=request.user, stat="OK")
    try:
        devs = get_user_online_devices([app.id for app in apps])
    except GatewayCallError as _:
        devs = []
    except GatewayTimeoutError as _:
        devs = []
    out = [{'chipid': el['chipid'],
            'appid': el['appid'],
            'appkey': appkey_from_appid(el['appid']),
            'vertype': ESPUSH_VERTYPE_MAP.get(el['vertype']),
            'latest': el['latest'],
            'devname': el['devname'],
            'appname': el['appname']} for el in devs]
    return JsonResponse(out, safe=False)


@sign_user_check
def user_apps(request):
    apps = App.objects.filter(user=request.user, stat='OK')
    outArray = [{
        'appid': el.id,
        'appkey': el.secret_key,
        'appname': el.app_name
                } for el in apps]
    return JsonResponse(outArray, safe=False)


@sign_check
def get_gpio_status(request, _chipid):
    chipid = to_int(_chipid)
    if not has_dev_permission(chipid, appobj=request.cur_app):
        logger.warn(u'无操作权限 [%d], [%d]', chipid, request.cur_app.id)
        return JsonResponse({"msg": "无设备对应操作权限！"},status=400)
    url = 'http://%s/_push_data?dev=%d&msgtype=%d' % (settings.SOCK_SERVER, chipid, 0x20)
    try:
        rsp = requests.post(url, timeout=5)
        if rsp.status_code != 200:
            logger.warn('服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn('服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    espush_gpio_map = [0, 1, 2, 3, 4, 5, 9, 10, 12, 13, 14, 15]
    '''
    		{0, FUNC_GPIO0, PERIPHS_IO_MUX_GPIO0_U},
		{1, FUNC_GPIO1, PERIPHS_IO_MUX_U0TXD_U},	//同是串口tx口
		{2, FUNC_GPIO2, PERIPHS_IO_MUX_GPIO2_U},	//uart1 RX口
		{3, FUNC_GPIO3, PERIPHS_IO_MUX_U0RXD_U},	//串口RX口
		{4, FUNC_GPIO4, PERIPHS_IO_MUX_GPIO4_U},
		{5, FUNC_GPIO5, PERIPHS_IO_MUX_GPIO5_U},
		//9 ~ 10
		{9, FUNC_GPIO9, PERIPHS_IO_MUX_SD_DATA2_U},
		{10, FUNC_GPIO10, PERIPHS_IO_MUX_SD_DATA3_U},
		//12~15
		{12, FUNC_GPIO12, PERIPHS_IO_MUX_MTDI_U},
		{13, FUNC_GPIO13, PERIPHS_IO_MUX_MTCK_U},
		{14, FUNC_GPIO14, PERIPHS_IO_MUX_MTMS_U},
		{15, FUNC_GPIO15, PERIPHS_IO_MUX_MTDO_U},
    '''
    if len(rsp.content[10:]) != len(espush_gpio_map):
        return JsonResponse({'msg': '服务端返回了错误的数据。'}, status=500)
    gpio_status_list = rsp.content[10:]
    # {pin: 0, edge: 1}
    outRsp = []
    for pos, byteVal in enumerate(gpio_status_list):
        outRsp.append({
            'pin': espush_gpio_map[pos],
            'edge': 1 if byteVal == '\x01' else 0
        })
    return JsonResponse(outRsp, safe=False)


@csrf_exempt
@sign_check
def color_change(request, _chipid, _channel, _newValue):
    channel = to_int(_channel)
    chipid = to_int(_chipid)
    newValue = to_int(_newValue)
    if channel not in [0, 1, 2]:
        return JsonResponse({'msg': 'CHANNEL ERROR.'}, status=400)
    if newValue > 8000:
        return JsonResponse({'msg': 'NEW VALUE too large.'}, status=400)
    if not has_dev_permission(chipid, appobj=request.cur_app):
        logger.warn(u'无操作权限 [%d], [%d]', chipid, request.cur_app.id)
        return JsonResponse({"msg": "无设备对应操作权限！"},status=400)
    url = 'http://%s/_push_data?dev=%d&msgtype=%d' \
          % (settings.SOCK_SERVER, chipid, 0x26)
    msg = struct.pack(b'!cIc', chr(0x11), newValue, chr(channel))
    try:
        rsp = requests.post(url, data=msg, timeout=50)
        if rsp.status_code != 200:
            logger.warn(u'网关返回错误，数据可能推送失败')
            return JsonResponse({'msg': "网关返回错误"}, status=504)
    except requests.Timeout as _:
        logger.error(u'网关请求超时')
        return JsonResponse({'msg': "网关请求超时"}, status=504)
    except IOError as _:
        logger.error(u'请求失败')
        return JsonResponse({'msg': "请求网关失败"}, status=504)
    return JsonResponse({'msg': 'OK'})
