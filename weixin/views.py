# encoding: utf-8

from __future__ import unicode_literals
from __future__ import print_function


import time
import uuid
import string
import random
import hashlib
import logging
import datetime


import redis
import requests


from django.shortcuts import render_to_response
from django.views.decorators.csrf import csrf_exempt
from django.template.context import RequestContext
from django.conf import settings
from django.contrib.auth import authenticate
from django.http.response import HttpResponse, HttpResponseBadRequest,\
    HttpResponseServerError, JsonResponse, HttpResponseRedirect,\
    HttpResponseForbidden

from contrib.tools import appkey_from_appid
from weixin.messages import parse_user_msg
from weixin.models import WechatUser, WechatToken, WechatFeedback
from weixin.reply import TextReply


from webv2.models import App
from webv2.views import get_user_online_devices
from contrib.exceptions import GatewayCallError, GatewayTimeoutError,\
    ServerConfigureException
from requests.exceptions import Timeout
import urllib


logger = logging.getLogger('espush')


def redis_client():
    return redis.Redis(host=settings.REDIS_HOST)


def generate_nonceStr():
    return ''.join([random.choice(string.ascii_lowercase) for _ in range(16)])


def token_auth(fn):
    def _wrapper(request, *args, **kwargs):
        now = datetime.datetime.now()
        token = request.META.get('HTTP_TOKEN')
        if not token:
            return HttpResponseBadRequest('Need Authorize.')
        try:
            tokenobj = WechatToken.objects.get(token=token,
                                               stat='VALID',
                                               expire_time__gt=now)
        except WechatToken.DoesNotExist as _:
            return HttpResponseForbidden('ERROR Authorize.')
        request.wechat_user = tokenobj.wechat_user
        return fn(request, *args, **kwargs)
    return _wrapper


def calculate_jsapi_sign(jsapi_ticket, url):
    noncestr = generate_nonceStr()
    timestamp = int(time.time())
    params = {
        'nonceStr': noncestr,
        'jsapi_ticket': jsapi_ticket,
        'timestamp': timestamp,
        'url': url
    }
    sOut = '&'.join(['%s=%s' % (key.lower(), params[key])
                     for key in sorted(params)])
    params['signature'] = hashlib.sha1(sOut).hexdigest()
    return params


def jssdk_cfg_ctx(request):
    protocol = 'https://' if request.is_secure else 'http://'
    host = request.get_host()
    full_path = request.get_full_path()
    url = '%s%s%s' % (protocol, host, full_path)
    r1 = redis_client()
    ticket = r1.get('WECHAT_ESPUSH_JSAPI_TICKET')
    if not ticket:
        logger.error('服务器未配置 TICKET')
        raise Exception("服务器未配置 TICKET")
    jssdk_cfg = calculate_jsapi_sign(ticket, url)
    logger.info('jssdk_cfg: %r', jssdk_cfg)
    return {
        'jssdk_cfg': jssdk_cfg,
        'appid': r1.get('WECHAT_ESPUSH_APPID')
    }


def wechat_get_user(openid):
    wechat_users = WechatUser.objects.filter(openid=openid,
                                             stat='VALID')
    if not wechat_users:
        logger.warn('微信用户 [%s] 初始化', openid)
        wechat_user = WechatUser(openid=openid, stat='VALID')
        wechat_user.save()
    else:
        wechat_user = wechat_users[0]
    return wechat_user


def get_gpio_status(chipid):
    url = 'http://%s/_push_data?dev=%d&msgtype=%d' % (settings.SOCK_SERVER,
                                                      chipid, 0x20)
    try:
        rsp = requests.post(url, timeout=5)
    except Timeout as _:
        raise GatewayTimeoutError('网关请求超时')
    if rsp.status_code != 200:
        logger.warn('服务端错误')
        raise GatewayCallError('服务端错误')
    return rsp.content[10:]


def set_gpio_status(chipid, pin, edge):
    assert(isinstance(chipid, int))
    assert(isinstance(pin, int))
    assert(isinstance(edge, int))
    assert(edge in [0, 1])
    url = 'http://%s/_push_data?dev=%d&msgtype=%d' % (settings.SOCK_SERVER,
                                                      chipid, 0x1E)
    body = chr(pin) + chr(edge)
    try:
        rsp = requests.post(url, data=body, timeout=5)
        if rsp.status_code != 200:
            logger.warn('服务端错误')
            raise GatewayCallError('服务端调用返回错误')
    except requests.Timeout as _:
        logger.warn('服务端超时')
        raise GatewayTimeoutError('服务端调用超时')
    return rsp.content[10:]


def md5(x):
    return hashlib.md5(x).hexdigest()


def to_int(s):
    try:
        return int(s)
    except ValueError as _:
        return None
    except TypeError as _:
        return None


def get_wechat_redirect_url(url):
    r1 = redis_client()
    appid = r1.get('WECHAT_ESPUSH_APPID')
    if not appid:
        logger.error('服务器端 APPID 未配置')
        raise ServerConfigureException('服务器APPID 未配置')
    quoted_url = urllib.quote(url, safe='')
    return ("https://open.weixin.qq.com/connect/oauth2/authorize?appid=" +
            appid + "&redirect_uri=" + quoted_url +
            "&response_type=code&scope=snsapi_base"
            "&state=SUCCESS#wechat_redirect")


def wechat_web_access_token(fn):
    def _wrapper(request, **kwargs):
        r1 = redis_client()
        appid = r1.get('WECHAT_ESPUSH_APPID')
        if not appid:
            logger.error('服务器端 APPID 未配置')
            return JsonResponse({'msg': 'server appid configure error.'},
                                status=500)
        secret = r1.get('WECHAT_ESPUSH_SECRET_KEY')
        if not secret:
            logger.error('服务器端 secret key 未配置')
            return JsonResponse({'msg': 'server secret configure error.'},
                                status=500)
        code = request.GET.get('code')
        if not code:
            logger.warn('从PC访问微信页面，重定向至微信首页')
            return HttpResponseRedirect("/weixin/")
        logger.info('appid: [%s], secret: [%s], code: [%s]',
                    appid, secret, code)
        baseurl = 'https://api.weixin.qq.com/sns/oauth2/access_token'
        params = {
            'appid': appid,
            'secret': secret,
            'code': code,
            'grant_type': 'authorization_code'
        }
        rsp = requests.get(baseurl, params=params)
        if rsp.status_code != 200:
            logger.warn('请求 web access token 失败, [%d], [%s]',
                        rsp.status_code, rsp.content)
            return HttpResponseRedirect("/weixin/")
        rspobj = rsp.json()
        if 'openid' not in rspobj:
            logger.warn('请求web access token 结果中未发现 openid [%s]',
                        rsp.content)
            return HttpResponseRedirect("/weixin/")
        openid = rspobj.get('openid')
        wechat_users = WechatUser.objects.filter(openid=openid,
                                                 stat='VALID')
        if not wechat_users:
            logger.warn('微信用户 [%s] 初始化', openid)
            wechat_user = WechatUser(openid=openid, stat='VALID')
            wechat_user.save()
        else:
            wechat_user = wechat_users[0]
        request.wechat_openid = openid
        request.wechat_user = wechat_user
        # JS SDK 初始化
        return fn(request, **kwargs)
    return _wrapper


def unsubscribe_msg(request, msg):
    user_openid = msg.source
    wechat_users = WechatUser.objects.filter(openid=user_openid,
                                             stat='VALID')
    if not wechat_users:
        logger.warn('未保存的微信用户 [%s] 取消关注', user_openid)
    else:
        wechat_user = wechat_users[0]
        wechat_user.stat = 'UNFOLLOWED'
        wechat_user.save()
    retmsg = TextReply(message=msg, content='bye')
    return HttpResponse(retmsg.render())


def subscribe_msg(request, msg):
    user_openid = msg.source
    wechat_get_user(user_openid)
    welcome_url = 'https://espush.cn/weixin/wechat_webapp/'
    quoted_welcome_url = get_wechat_redirect_url(welcome_url)
    content = """欢迎关注ESPUSH
ESPUSH 是专门为ESP8266 WIFI物联网而开发的云平台，针对云端远程控制、数据采集等应用场景做了深度优化。
<a href="%s">点这里手机控制您的WIFI</a>
有什么意见，您也可以直接微信与我沟通，收到您的反馈后我会尽快回复您。
    """ % quoted_welcome_url
    retmsg = TextReply(message=msg, content=content)
    return HttpResponse(retmsg.render())


@csrf_exempt
def wechat(request):
    r1 = redis_client()
    WECHAT_TOKEN = r1.get('WECHAT_ESPUSH_TOKEN')
    if not WECHAT_TOKEN:
        logger.error('未配置TOKEN,失败')
        return HttpResponseServerError("服务端错误，未配置")
    signature = request.GET.get('signature')
    timestamp = request.GET.get('timestamp')
    nonce = request.GET.get('nonce')
    echostr = request.GET.get('echostr')
    if (not nonce) or (not timestamp) or (not signature):
        return HttpResponseBadRequest('ERROR')
    sOut = hashlib.sha1(''.join(sorted([WECHAT_TOKEN,
                                        timestamp, nonce]))).hexdigest()
    logger.info('signature: [%s], [%s]', signature, sOut)
    if sOut != signature:
        logger.warn('签名不正确，忽略')
        return HttpResponseBadRequest("ERROR")
    if request.method == 'GET':
        return HttpResponse(echostr)
    if request.method == 'POST':
        msg = parse_user_msg(request.body)
        logger.info(u'消息: [%s]', msg.type)
        if msg.type == 'subscribe':
            return subscribe_msg(request, msg)
        elif msg.type == 'unsubscribe':
            return unsubscribe_msg(request, msg)
        elif msg.type == 'view':
            logger.info('页面跳转事件，忽略')
            return HttpResponse("")
        elif msg.type == 'text':
            logger.info('用户直接沟通反馈')
            weuser = wechat_get_user(msg.source)
            feedback_msg = WechatFeedback(
                content=msg.content,
                wechat_user=weuser
            )
            feedback_msg.save()
            rsp_content = '小E已经收到您的呼唤，我会尽快给您回复'
            rsp = TextReply(message=msg, content=rsp_content)
            return HttpResponse(rsp.render())
        else:
            logger.warn('未知消息类型')
            content = '小E也不知道您在嘀咕个啥'
            rsp = TextReply(message=msg, content=content)
            return HttpResponse(rsp.render())


@wechat_web_access_token
def bind_user(request):
    ctx = {}
    ctx['openid'] = request.wechat_openid
    rsp_inst = RequestContext(request, processors=[jssdk_cfg_ctx, ])
    if request.wechat_user.user:
        return render_to_response('weixin/binded.html', ctx, context_instance=rsp_inst)
    if request.method == 'GET':
        return render_to_response('weixin/bind_user.html', ctx, context_instance=rsp_inst)


@csrf_exempt
def bind_user_req(request):
    openid = request.POST.get('openid')
    wechat_users = WechatUser.objects.filter(openid=openid, stat='VALID')
    if not wechat_users:
        logger.warn('微信用户 [%s] 初始化', openid)
        wechat_user = WechatUser(openid=openid, stat='VALID')
        wechat_user.save()
    else:
        wechat_user = wechat_users[0]
    email = request.POST.get('email')
    password = request.POST.get('password')
    if not openid or not email or not password:
        return HttpResponseBadRequest('参数不完整')
    password = hashlib.md5(password).hexdigest()
    userobj = authenticate(username=email, password=password)
    if not userobj:
        return HttpResponseForbidden(u'用户名或密码错误')
    if userobj.stat != 'OK':
        return HttpResponseForbidden(u'用户已失效')
    wechat_user.user = userobj
    wechat_user.save()
    return HttpResponse('OK')


@wechat_web_access_token
def register_user(request):
    return render_to_response('webv2/register.html')


@wechat_web_access_token
def forgot(request):
    return render_to_response('webv2/forgot.html')


@wechat_web_access_token
def network_config(request):
    ctx = {}
    rsp_inst = RequestContext(request, processors=[jssdk_cfg_ctx, ])
    return render_to_response('weixin/smartconfig.html', ctx, context_instance=rsp_inst)


@wechat_web_access_token
def home(request):
    return render_to_response('weixin/home.html')


def redirect_docs(request):
    return HttpResponseRedirect(settings.DOCS_WEBSITE)


@wechat_web_access_token
def wechat_webapp(request):
    r1 = redis_client()
    appid = r1.get('WECHAT_ESPUSH_APPID')
    if not appid:
        logger.error('服务器端 APPID 未配置')
        return HttpResponseBadRequest('''
        <script>alert('服务器配置错误，请联系管理员')</script>
        ''')
    bind_user_baseurl = 'https://espush.cn/weixin/wechat_bind_user/'
    bind_user_url = get_wechat_redirect_url(bind_user_baseurl)
    if request.wechat_user.user is None:
        return HttpResponseRedirect(bind_user_url)
    # FIND TOKEN
    now = datetime.datetime.now()
    tokenobjs = WechatToken.objects.filter(stat='VALID',
                                           wechat_user=request.wechat_user,
                                           expire_time__gt=now)
    if not tokenobjs:
        # if not ,then create one. md5(uuid)
        token_str = md5(uuid.uuid1().get_bytes())
        tokenobj = WechatToken(
            wechat_user=request.wechat_user,
            token=token_str,
            create_time=now,
            expire_time=now + datetime.timedelta(hours=3),
            stat='VALID'
        )
        tokenobj.save()
    else:
        tokenobj = tokenobjs[0]
    token = tokenobj.token
    return HttpResponseRedirect('/weixin/webapp/?token=%s&_=%s' %
                                (token, str(int(time.time()))))


@token_auth
def api_devices_online(request):
    apps = App.objects.filter(user=request.wechat_user.user, stat="OK")
    try:
        devs = get_user_online_devices([app.id for app in apps])
    except GatewayCallError as _:
        devs = []
    except GatewayTimeoutError as _:
        devs = []
    out = [{'chipid': el['chipid'],
            'appid': el['appid'],
            'appkey': appkey_from_appid(el['appid']),
            'vertype': el['vertype'],
            'latest': el['latest'],
            'devname': el['devname'],
            'appname': el['appname']} for el in devs]
    return JsonResponse(out, safe=False)


@token_auth
def api_device_pins(request, chipid):
    pins = get_gpio_status(to_int(chipid))
    pin_idx = [0, 1, 2, 3, 4, 5, 9, 10, 12, 13, 14, 15]
    logger.info('PINS LENGTH: [%d]', len(pins))
    if len(pin_idx) != len(pins):
        logger.warn('GPIO 引脚值定义错误 %s', repr(pins))
        return HttpResponseBadRequest('GPIO 读取错误')
    pins_bool = [True if ord(word) else False for word in pins]
    pins_obj = dict(zip(pin_idx, pins_bool))
    outArr = [{'val': idx, 'edge': pins_obj[idx]} for idx in pins_obj]
    return JsonResponse(outArr, safe=False)


@csrf_exempt
@token_auth
def api_device_set_pin_edge(request, chipid, pin, edge):
    if edge not in ['1', '0']:
        logger.warn('电平态只能为0 或 1')
        return JsonResponse({"msg": "电平态只能为0 或 1"}, status=400)
    try:
        set_gpio_status(to_int(chipid), int(pin), int(edge))
    except GatewayCallError as _:
        return JsonResponse({"msg": "服务器端操作失败，请检查设备是否在线"}, status=500)
    except GatewayTimeoutError as _:
        return JsonResponse({"msg": "服务器端操作超时！"}, status=500)
    return HttpResponse('OK')


@token_auth
def api_dht_value(request, chipId):
    chipid = to_int(chipId)
    url = 'http://%s/_push_data?dev=%d&msgtype=%d' % (settings.SOCK_SERVER, chipid, 0x1C)
    try:
        rsp = requests.post(url, data="KEY", timeout=5)
        if rsp.status_code != 200:
            logger.warn('服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn('服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    try:
        result = rsp.content[11:].replace('\x00', '').split('===')
        return JsonResponse({
            'temperature': to_int(result[0]) / 100,
            'humidity': to_int(result[1]) / 100
        })
    except Exception:
        return JsonResponse({'msg': '设备数据获取错误'}, status=500)


@csrf_exempt
@token_auth
def api_gpio16_change(request, chipId, edge):
    chipid = to_int(chipId)
    at_cmd = 'AT+LED=%d\r\n' % to_int(edge)
    url = 'http://%s/_push_data?dev=%d&msgtype=%d'\
        % (settings.SOCK_SERVER, chipid, 0x14)
    try:
        rsp = requests.post(url, data=at_cmd, timeout=50)
        if rsp.status_code != 200:
            logger.warn(u'网关返回错误，数据可能推送失败')
            return JsonResponse({'msg': "网关返回错误"}, status=504)
    except requests.Timeout as _:
        logger.error(u'网关请求超时')
        return JsonResponse({'msg': "网关请求超时"}, status=504)
    except IOError as _:
        logger.error(u'请求失败')
        return JsonResponse({'msg': "请求网关失败"}, status=504)
    return JsonResponse({
        "msg": "OK"
    })
