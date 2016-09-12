# -*- coding: UTF-8 -*-

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division


import os
import uuid
import time
import urllib
import random
import urllib2
import hashlib
import logging
import requests
import datetime
import binascii
import json

from cStringIO import StringIO

from PIL import Image, ImageDraw, ImageFont, ImageFilter

import redis

from django.template.context import RequestContext
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render_to_response
from django.conf import settings
from django.http.response import HttpResponseRedirect, HttpResponse,\
    HttpResponseForbidden, HttpResponseServerError, HttpResponseNotFound,\
    JsonResponse, Http404, HttpResponseBadRequest, HttpResponseNotAllowed
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http.request import QueryDict
from django.views.decorators.http import require_POST
from django.core.urlresolvers import reverse

from contrib.tools import make_down_available_rsp, get_user_online_devices
from contrib.utils import reqjson, wechat_userinfo_batchget
from webv2.common import ajax_return, common_cmd_push_single_dev
from webv2.models import User, App, Message, Device, UPLOAD_MSG,\
    TimerTaskRule, EspRom
from contrib.exceptions import ArgumentError, AppNotFoundExp, MultiAppFoundExp,\
    DeviceNotFoundExp, MultiDeviceFoundExp, GatewayTimeoutError,\
    GatewayCallError, EspushException
from weixin.models import WechatUser

# Create your views here.
logger = logging.getLogger('espush')


def md5(x):
    return hashlib.md5(x).hexdigest()


def to_int(s):
    try:
        return int(s)
    except ValueError as _:
        return None
    except TypeError as _:
        return None


def deserialize_datetime(s, fmt):
    try:
        return datetime.datetime.strptime(s, fmt)
    except Exception as _:
        return None

def admin_required(func):
    def _wrapper(request, *args, **kwargs):
        if request.user.is_authenticated() and request.user.is_admin:
            return func(request, *args, **kwargs)
        return HttpResponseRedirect(reverse('webv2_index'))
    return _wrapper


def timer_task_call(func, method, args):
    url = 'http://localhost:9999/' + func
    try:
        return requests.request(method, url, data=args)
    except requests.Timeout:
        raise GatewayTimeoutError('定时任务服务器响应超时')
    except requests.exceptions.BaseHTTPError as _:
        raise GatewayCallError('定时认为服务器响应失败')
    except Exception as _:
        logger.error('请求定时任务服务器，未知错误')
        raise EspushException('服务端定时任务服务器，未知错误')


def new_task_backend(category, timeval, pin, edge):
    args = {'category': category, 'val': timeval, 'pin': pin, 'edge': edge}
    rsp = timer_task_call('add', 'POST', args)
    if rsp.status_code != 200:
        logger.warn('定时任务接口调用错误')
        raise GatewayCallError('定时任务接口调用错误: %s' % rsp.content)
    rspobj = rsp.json()
    if 'jobid' not in rspobj:
        logger.warn('定时任务服务器调用后返回结果无jobid，错误')
        raise GatewayCallError('定时任务服务器调用后返回结果无jobid')
    return rspobj['jobid']


def remove_task(jobid):
    args = {'jobid': jobid}
    rsp = timer_task_call('del', 'POST', args)
    if rsp.status_code != 200:
        logger.warn('定时任务接口调用错误')
        raise GatewayCallError('定时任务接口调用错误: %s' % rsp.content)
    return rsp.json()


@login_required
def index(request):
    return render_to_response('webv2/index.html',
                              {}, RequestContext(request))


def site_index(request):
    return render_to_response('webv2/site_index.html',
                              {}, RequestContext(request))


@login_required
def apps_view(request):
    context = {}
    if request.method == 'GET':
        context['apps'] = App.objects.filter(user=request.user, stat="OK")
        return render_to_response('webv2/apps.html', context,
                                  RequestContext(request))
    if request.method == 'POST':
        app_name = request.POST.get('app', '')
        if not app_name:
            HttpResponseForbidden(u'''
            <script>alert(u'app不能为空');window.location.href="";</script>
            ''')
        secret_key = uuid.uuid1().get_hex()
        app = App.objects.filter(user=request.user,
                                 app_name=app_name, stat="OK")
        if app:
            return HttpResponseForbidden(u'''
            <script>alert("app名称重复");window.location.href='';</script>
            ''')
        app = App(app_name=app_name,
                  secret_key=secret_key,
                  user=request.user,
                  stat="OK")
        app.save()
        return HttpResponseRedirect(reverse('webv2_apps'))


def loginview(request):
    if request.method == 'GET':
        # 如果已登录，则直接控制跳转
        if request.user.is_authenticated():
            return HttpResponseRedirect(reverse('webv2_index'))
        return render_to_response('webv2/login.html',
                                  RequestContext(request, {}))
    if request.method == 'POST':
        email = request.POST.get('email', '')
        if not email:
            return HttpResponseForbidden(u'''
            <script>alert('email不能为空');window.location.href="";</script>
            ''')
        password = request.POST.get('password', '')
        if not password:
            return HttpResponseForbidden(u'''
            <script>alert('密码不能为空');window.location.href="";</script>
            ''')
        password = hashlib.md5(password).hexdigest()
        userobj = authenticate(username=email, password=password)
        if not userobj:
            return HttpResponseForbidden(u'''
            <script>alert('用户名或密码错误');window.location.href="";</script>
            ''')
        if userobj.stat != 'OK':
            return HttpResponseForbidden(u'''
            <script>alert('用户已不存在');window.location.href="";</script>
            ''')
        remember = request.POST.get("remember")
        if not remember:
            request.session.set_expiry(0)
        login(request, userobj)
        if 'next' in request.GET:
            url = request.GET['next']
        else:
            url = reverse('webv2_index')
        return HttpResponseRedirect(url)


def logoutview(request):
    logout(request)
    return HttpResponseRedirect(reverse('webv2_login'))


def send_wellcome_mail(email):
    content = """您好，我是espush.cn的开发者，欢迎您使用 espush.cn 云。
espush是针对ESP8266无线WIFI芯片开发的一款便捷的云服务平台（最初做为简单的推送平台出现，故名为push而非cloud），您可以浏览我们的博客关注更多动态，或给我们留言，这是我的github帐号pushdotccgzs，有固件源码、手机APP源码，路过star哦。
使用手机APP或服务端api，可以在任何地方，轻松控制WIFI设备。关于espush的任何bug报告，或建议，都是欢迎的。

当然，不要回复此邮件，咨询合作或联系我可以使用此地址：webmaster@espush.cn，感谢您的关注，最后，祝玩的愉快。

ESPUSH is a IOT development platform,it havs real-time remote data push, intelligent data acquisition and induction, the cloud automatically push upgrades, and other functions.

ESPUSH only wants to solve a problem, that is, can control WIFI devices at any time in any network. Such as using company WIFI control homerobot car, on the way home use 4 g networks open the water heater and air conditioner in advance, etc.Tutorial here.
"""
    html_content = """您好，我是espush.cn的开发者，欢迎您使用 espush.cn 云。<br />
espush是针对ESP8266无线WIFI芯片开发的一款便捷的云服务平台（最初做为简单的推送平台出现，故名为push而非cloud），您可以浏览我们的博客关注更多动态，或给我们留言，这是我的github帐号pushdotccgzs，有固件源码、手机APP源码，路过star哦。<br />
使用手机APP或服务端api，可以在任何地方，轻松控制WIFI设备。关于espush的任何bug报告，或建议，都是欢迎的。<br />
<br />
当然，不要回复此邮件，咨询合作或联系我可以使用此地址：webmaster@espush.cn，感谢您的关注，最后，祝玩的愉快。<br />
<br />
ESPUSH is a IOT development platform,it havs real-time remote data push, intelligent data acquisition and induction, the cloud automatically push upgrades, and other functions.<br />
<br />
ESPUSH only wants to solve a problem, that is, can control WIFI devices at any time in any network. Such as using company WIFI control homerobot car, on the way home use 4 g networks open the water heater and air conditioner in advance, etc.Tutorial here.<br />"""
    mailobj = {
        'from': "espush robot <admin@email.espush.cn>",
        'to': email,
        "subject": "欢迎注册espush.cn",
        "text": content,
        "html": html_content
    }
    r = redis.Redis(host='localhost')
    r.lpush('queue.mail', json.dumps(mailobj))


def register(request):
    if request.method == 'GET':
        return render_to_response('webv2/register.html',
                                  RequestContext(request, {}))
    elif request.method == 'POST':
        email = request.POST.get('email', '')
        if not email:
            return HttpResponseForbidden(u'''
            <script>alert('邮箱不能为空');window.location.href="";</script>
            ''')
        password = request.POST.get('password', '')
        if not password:
            return HttpResponseForbidden(u'''
            <script>alert('密码不能为空');window.location.href="";</script>
            ''')
        password = hashlib.md5(password).hexdigest()
        users = User.objects.filter(email=email, stat='OK')
        if users:
            return HttpResponse(u'''
            <script>alert('已有账户？请直接登陆即可');window.location.href="";</script>
            ''', status=400)
        else:
            User.objects.create_user(email, password, 'OK')
            # send_wellcome_mail(email)
            login_user = authenticate(username=email, password=password)
            login(request, login_user)
        return HttpResponseRedirect(reverse('webv2_index'))


@csrf_exempt
@login_required
def pushmsg_single_dev(request, appid, chipid):
    msg = request.POST.get("msg")
    if not msg:
        logger.warn(u'推送数据为空，拒绝')
        return HttpResponseForbidden(u"推送数据为空")
    msg = msg.encode("GBK")
    chipid = to_int(chipid)
    if not chipid:
        logger.warn(u'错误的模块芯片号')
        return HttpResponseForbidden(u"模块芯片号格式错误")
    appid = to_int(appid)
    if not appid:
        logger.warn(u'错误的设备类别编号')
        return HttpResponseForbidden(u"设备类别编号格式错误")
    try:
        appobj = App.objects.get(id=appid, stat='OK')
    except App.DoesNotExist as _:
        logger.warn(u'APP 未找到 %d', appid)
        return HttpResponseNotFound(u'设备类别未找到')
    except App.MultipleObjectsReturned as _:
        logger.warn(u'APP 相同记录 [%d]', appid)
        return HttpResponseServerError(u'服务器数据错误')
    if appobj not in request.user.app_set.all():
        logger.warn(u'无对应权限向设备推送消息 %d, %d', appid, chipid)
        return HttpResponseNotAllowed(u'无权向此设备推送数据')
    msgformat = request.POST.get('format')
    if not format:
        logger.info(u'未选择指令类型，默认为文本')
        msgformat = u'MSG'
    if msgformat not in [u'MSG', u'HEX', u'AT', u'LUA']:
        logger.info(u'指令类型错误')
        return HttpResponseForbidden(u"指令类型错误")
    if msgformat == u'HEX':
        if len(msg) % 2:
            logger.warn(u'十六进制原始数值长度需为偶数')
            return HttpResponseForbidden(u"十六进制原始数值长度需为偶数")
        try:
            msg = binascii.a2b_hex(msg)
        except Exception as _:
            logger.warn(u'十六进制数值错误')
            return HttpResponseForbidden(u"无法解析十六进制值")
    if msgformat == u'AT':
        if len(msg) > 64 and ('\r' in msg or '\n' in msg):
            logger.info(u'AT指令长度不得超过64字节，且不得换行')
            return HttpResponseForbidden(u"AT指令长度不得超过64字节，且不得换行")
    if msgformat == u'AT':
        msgtype = 0x14
        msg += '\r\n'
    elif msgformat in [u'MSG', u'HEX']:
        msgtype = 0x04
    elif msgformat == u'LUA':
        msgtype = 0x16
    url = 'http://%s/_push_data?dev=%d&msgtype=%d' %\
        (settings.SOCK_SERVER, chipid, msgtype)
    # 发出网络请求, 推送数据
    try:
        rsp = requests.post(url, data=msg, timeout=10)
        if rsp.status_code != 200:
            logger.warn(u'网关返回错误，数据可能推送失败')
            return HttpResponse(u"网关返回错误", status=504)
    except requests.Timeout as _:
        logger.error(u'网关请求超时')
        return HttpResponse(u"网关请求超时", status=504)
    except IOError as _:
        logger.error(u'请求失败')
        return HttpResponse(u"请求网关失败", status=504)
    # 新建数据库记录 以供浏览
    try:
        dev_db = Device.objects.get(chip=chipid, app=appobj)
    except Device.DoesNotExist as _:
        dev_db = Device(chip=chipid, app=appobj, stat="OK")
        dev_db.save()
    except Device.MultipleObjectsReturned as _:
        logger.error('服务器逻辑错误，存在相同记录')
        return HttpResponseServerError("ERROR")
    now = datetime.datetime.now()
    if isinstance(msg, unicode):
        msg = msg.encode('utf-8')
    record = Message(dev=dev_db,
                     msgtype='PUSH_DEV',
                     category='MSG',
                     create_time=now,
                     recv_time=now,
                     msg=msg,
                     user=request.user,
                     stat="OK")
    record.save()
    return HttpResponse(u"OK")


@csrf_exempt
@login_required
def pushmsg(request):
    if request.method == 'GET':
        context = {}
        apps = App.objects.filter(user=request.user, stat="OK")
        context['apps'] = apps
        return render_to_response('web/pushmsg.html', context,
                                  RequestContext(request))
    if request.method == 'POST':
        app = request.POST.get('app', '')
        msg = request.POST.get('msg', '')
        # 检查APP传值
        if not app:
            return HttpResponseForbidden(u"目标设备APP不得为空")
        appid = to_int(app)
        if not appid:
            return HttpResponseForbidden(u'目标设备APP错误')
        try:
            app_db = App.objects.get(id=appid, stat="OK")
        except App.DoesNotExist as _:
            logger.warn(u'无效设备号，数据库记录不存在')
            return HttpResponseForbidden(u"目标设备APP编号不存在")
        except App.MultipleObjectsReturned as _:
            logger.error(u'数据库中对同一APP有多条记录，错误 [%d]' % appid)
            return HttpResponseServerError(u"error")
        # 检查MSG传值
        if not msg:
            return HttpResponseForbidden(u"推送内容不得为空")
        msg = msg.encode('GBK')
        url = 'http://%s/pushmsg?app=%d' % (settings.SOCK_SERVER, appid)
        try:
            rsp = requests.post(url, data=msg, timeout=1)
            if rsp.status_code != 200:
                return HttpResponseServerError(u"服务端错误")
        except requests.Timeout as _:
            return HttpResponseServerError(u"服务端超时")
        if isinstance(msg, unicode):
            msg = msg.encode('utf-8')
        record = Message(app=app_db,
                         msgtype='PUSH_APP',
                         category='MSG',
                         create_time=datetime.datetime.now(),
                         msg=msg,
                         user=request.user,
                         stat="OK")
        record.save()
        return HttpResponse(u"sucess")


@login_required
def devices(request):
    context = {}
    apps = App.objects.filter(user=request.user, stat="OK")
    context['apps'] = apps
    try:
        context['devs'] = get_user_online_devices([app.id for app in apps])
    except GatewayCallError as _:
        context['devs'] = []
    except GatewayTimeoutError as _:
        context['devs'] = []
    return render_to_response('webv2/devices.html',
                              context, RequestContext(request))


@login_required
def otaview(request):
    # post 文件上传，包含user1 与user2
    if request.method == 'POST':
        user1 = request.FILES.get('user1')
        user2 = request.FILES.get('user2')
        if not user1 or not user2:
            return HttpResponseForbidden('''
            <script>
                alert("文件为空，上传错误");
                window.location.href='';
            </script>
            ''')
        ver_name = request.POST.get('version')
        if not ver_name:
            return HttpResponseForbidden('''
            <script>
                alert("请确认正确的上传版本号, 不能为空值");
                window.location.href='';
            </script>
            ''')
        user1_content = user1.read()
        user2_content = user2.read()
        user1_filename = md5(user1_content)
        user2_filename = md5(user2_content)
        user1_path = os.path.join(settings.UPLOAD_DIR, user1_filename)
        user2_path = os.path.join(settings.UPLOAD_DIR, user2_filename)
        if not os.path.exists(user1_path):
            with open(user1_path, 'wb') as f1:
                f1.write(user1_content)
        if not os.path.exists(user2_path):
            with open(user2_path, 'wb') as f2:
                f2.write(user2_content)
        # db_case = OTACase(ver_name=ver_name,
        #                   user=request.user,
        #                   user1=user1_path,
        #                   user2=user2_path,
        #                   create_time=datetime.datetime.now(),
        #                   stat='OK')
        # db_case.save()
        return HttpResponseRedirect("/web/ota/")
    # get 页面
    context = {}
    # context['casies'] = OTACase.objects.filter(user=request.user, stat="OK")
    return render_to_response('web/ota.html', context, RequestContext(request))


@login_required
def history_push(request):
    limit = 15
    c = {}
    records = Message.objects.filter(user=request.user)\
        .filter(stat='OK').order_by('-create_time')
    paginator = Paginator(records, limit)
    page = request.GET.get('page')
    pagenum = to_int(page)
    if not page:
        return HttpResponseRedirect("?page=1")
    try:
        c['records'] = paginator.page(pagenum)
    except PageNotAnInteger:
        return HttpResponseRedirect("?page=1")
    except EmptyPage:
        return HttpResponseRedirect("?page=%d" % (paginator.num_pages))
    return render_to_response('webv2/history_push.html',
                              c, RequestContext(request))


@login_required
def dev_data(request):
    limit = 15
    c = {}
    apps = App.objects.filter(user=request.user)
    records = UPLOAD_MSG.objects.filter(app__in=apps).order_by('-create_time')
    paginator = Paginator(records, limit)
    page = request.GET.get('page')
    pagenum = to_int(page)
    if not page:
        return HttpResponseRedirect("?page=1")
    try:
        c['records'] = paginator.page(pagenum)
    except PageNotAnInteger:
        return HttpResponseRedirect("?page=1")
    except EmptyPage:
        return HttpResponseRedirect("?page=%d" % (paginator.num_pages))
    return render_to_response('webv2/dev_data.html',
                              c,
                              RequestContext(request))


@csrf_exempt
@login_required
def remove_app(request, appid):
    try:
        app = App.objects.get(id=appid)
        app.stat = 'DELETED'
        app.save()
    except App.DoesNotExist as _:
        return HttpResponseForbidden(u"设备不存在")
    except App.MultipleObjectsReturned as _:
        return HttpResponseForbidden(u"服务端有多个同编号设备，服务器出错")
    return HttpResponse("OK")


def faq_img_view(request, img):
    docs_path = os.path.join(settings.BASE_DIR, 'docs')
    img_path = os.path.join(docs_path, img)
    with open(img_path, 'rb') as f1:
        img = f1.read()
        return HttpResponse(img, content_type="image/png")
    return HttpResponseNotFound("NOT FOUND.")


def down_latest_rom(request, category):
    outpath = settings.ROMS_UPLOAD_DIR
    romdbobjs = EspRom.objects.filter(name=category)
    if not romdbobjs:
        return  HttpResponseNotFound("Not Found...")
    romdb = romdbobjs.order_by("-id")[0]
    return make_down_available_rsp(outpath, romdb.rom)


def hash_roms(request):
    roms = [u'espush_at', u'espush_nodemcu']
    down_path = os.path.join(settings.BASE_DIR, 'down_roms')
    retobj = {}
    for rom in roms:
        filename = '%s.tar.gz' % rom
        file_path = os.path.join(down_path, filename)
        with open(file_path, 'rb') as f1:
            hash_str = md5(f1.read())
            retobj[rom] = hash_str
    return JsonResponse(retobj, safe=False)


def down_apk(request):
    types = 'application/octet-stream'
    filename = 'app-release.apk'
    down_path = os.path.join(settings.BASE_DIR, 'resources/androidapp')
    file_path = os.path.join(down_path, filename)
    with open(file_path, 'rb') as f1:
        rsp = HttpResponse(f1.read(), content_type=types)
        rsp['Content-Disposition'] = 'filename=espush_client.apk'
        return rsp
    return HttpResponseNotFound("NOT FOUND..")


@login_required
def feedback(request):
    pass
    # context = {}
    # if request.method == 'GET':
    #     return render_to_response('web/feedback.html',
    #                               context, RequestContext(request))
    # title = request.POST.get('title')
    # body = request.POST.get('body')
    # if not title and not body:
    #     return HttpResponseForbidden('''
    #     <script>
    #         alert("希望您多多少少说点儿");
    #         window.location.href='';
    #     </script>
    #     ''')
    # feedback = FEEDBACK(
    #     user=request.user,
    #     title=title,
    #     body=body
    # )
    # feedback.save()
    # return HttpResponse('''
    # <script>
    #     alert("谢谢您的反馈，您的意见我会认真考虑的，您可以直接Q我： 312 694 652，备注espush即可");
    #     window.location.href='';
    # </script>
    # ''')


@csrf_exempt
@login_required
def note_name(request, appid, chipid):
    name = request.POST.get('name')
    if not name:
        logger.warn('name值为空，不允许')
        return HttpResponseForbidden("ERROR, NAME EMPTY")
    try:
        app_db = App.objects.get(id=appid)
    except App.DoesNotExist as _:
        logger.warn(u'设备备注, 未找到APP')
        return HttpResponseNotFound("ERROR, APP EMPTY.")
    devs = Device.objects.filter(chip=chipid).filter(app=app_db)
    if not devs:
        logger.warn('暂未发现此设备')
        return HttpResponseNotFound("ERROR, NAME EMPTY")
    devs.update(name=name)
    return HttpResponse("OK")


@csrf_exempt
@login_required
def dev_refresh(request, chipid):
    chip = to_int(chipid)
    url = 'http://%s/dev_refresh?chipid=%d' % (settings.SOCK_SERVER, chip)
    # 发出网络请求, 推送数据
    try:
        rsp = requests.post(url, timeout=8)
        if rsp.status_code != 200:
            logger.warn(u'网关返回错误，接口调用失败')
            return HttpResponse(u"网关返回错误", status=504)
    except requests.Timeout as _:
        logger.error(u'网关请求超时')
        return HttpResponse(u"网关请求超时", status=504)
    except IOError as _:
        logger.error(u'请求失败')
        return HttpResponse(u"请求网关失败", status=504)
    if rsp.content == 'offline':
        logger.info(u'设备 [%d] 已离线', chip)
        return HttpResponse('offline')
    logger.info(u'设备 [%d] 在线', chip)
    return HttpResponse('online')


@csrf_exempt
@login_required
def data_graphic(request):
    if request.method == 'GET':
        context = {}
        apps = App.objects.filter(user=request.user, stat="OK")
        context['apps'] = apps
        return render_to_response('webv2/data_graphic.html', context,
                                  RequestContext(request))
    # POST
    data_src = request.POST.get("data_src")
    if not data_src:
        logger.warn('data_src参数缺失')
        return JsonResponse({"msg": "参数错误"}, status=400)
    try:
        app_db = App.objects.get(id=data_src, user=request.user)
    except App.DoesNotExist as _:
        logger.warn('data_src 参数错误')
        return JsonResponse({"msg": "参数错误"}, status=400)
    data_tag = request.POST.get('data_tag')
    if not data_tag:
        logger.warn('data_tag参数缺失')
        return JsonResponse({"msg": "参数错误"}, status=400)
    _begin_date = request.POST.get('begin_date')
    if not _begin_date:
        logger.warn('begin_date参数缺失')
        return JsonResponse({"msg": "参数错误"}, status=400)
    begin_date = deserialize_datetime(_begin_date, "%Y-%m-%d")
    if not begin_date:
        logger.warn('begin_date 格式错误')
        return JsonResponse({"msg": "参数格式错误"}, status=400)
    _end_date = request.POST.get('end_date')
    if not _end_date:
        logger.warn('end_date参数缺失')
        return JsonResponse({"msg": "参数错误"}, status=400)
    end_date = deserialize_datetime(_end_date, "%Y-%m-%d")
    if not end_date:
        logger.warn('end_date 格式错误')
        return JsonResponse({"msg": "参数格式错误"}, status=400)
    upload_msg = UPLOAD_MSG.objects\
        .filter(app=app_db)\
        .filter(create_time__range=(begin_date, end_date))\
        .filter(stat='VALID')
    xSerial = [el.create_time.strftime("%Y-%m-%d %H:%M:%S")
               for el in upload_msg]
    ySerial = [str(el.body) for el in upload_msg]
    retobj = {
        'xSerial': xSerial,
        'ySerial': ySerial
    }
    return JsonResponse(retobj, safe=False)


@login_required
@csrf_exempt
def notice_opr(request, appid):
    pass
    # try:
    #     app_db = App.objects.get(id=appid)
    # except App.DoesNotExist as _:
    #     raise Http404()
    # if request.method == 'GET':
    #     notice_db_s = NoticeAPI.objects.filter(app=app_db, stat='VALID')
    #     if not notice_db_s:
    #         return JsonResponse({}, safe=False)
    #     notice_db = notice_db_s[0]
    #     return JsonResponse({'addr': notice_db.addr, 'token': notice_db.token})
    # elif request.method == 'PUT':
    #     putobj = QueryDict(request.body)
    #     addr = putobj.get('addr')
    #     if not addr:
    #         logger.warn(u'请求参数缺失addr')
    #         return JsonResponse({"msg": "addr empty"}, status=400)
    #     token = putobj.get('token')
    #     if not token:
    #         logger.warn(u'请求参数缺失token')
    #         return JsonResponse({"msg": "token empty"}, status=400)
    #     notice_db_s = NoticeAPI.objects.filter(app=app_db, stat='VALID')
    #     logger.info(u'TOKEN: [%s], ADDR: [%s]', token, addr)
    #     if not notice_db_s:
    #         notice_db = NoticeAPI(app=app_db,
    #                               addr=addr, token=token, stat='VALID')
    #         notice_db.save()
    #     else:
    #         notice_db = notice_db_s[0]
    #         notice_db.addr = addr
    #         notice_db.token = token
    #         notice_db.save()
    #     return JsonResponse({"msg": "Added"})
    # elif request.method == 'DELETE':
    #     notice_db_s = NoticeAPI.objects.filter(app=app_db, stat='VALID')
    #     if not notice_db_s:
    #         return JsonResponse({"msg": "OK"}, safe=False)
    #     notice_db = notice_db_s[0]
    #     notice_db.stat = 'DELETED'
    #     notice_db.save()
    #     return JsonResponse({"msg": "DELETED"})


def calculate_sign(method, params, appkey):
    stra = method.lower()
    keys = params.keys()
    keys.sort()
    keys.reverse()
    strb = '&'.join(['%s=%s'.lower() % (el, params[el]) for el in keys])
    strc = appkey.lower()
    return md5(stra + strb + strc)


@login_required
@csrf_exempt
def notice_api_test(request, appid):
    try:
        app_db = App.objects.get(id=appid)
    except App.DoesNotExist as _:
        raise Http404()
    addr = request.POST.get('addr')
    if not addr:
        logger.warn(u'请求参数缺失addr')
        return JsonResponse({"msg": "addr empty"}, status=400)
    if addr.startswith('https'):
        logger.warn(u'暂不支持https')
        return JsonResponse({"msg": "https not support."}, status=400)
    token = request.POST.get('token')
    if not token:
        logger.warn(u'请求参数缺失token')
        return JsonResponse({"msg": "token empty"}, status=400)
    timestamp = str(int(time.time()))
    'appid, sign, msg, timestamp, token'
    params = {
        'appid': app_db.id,
        'timestamp': timestamp,
        'token': token
    }
    sign = calculate_sign('get', params, app_db.secret_key)
    params['sign'] = sign
    try:
        rsp = requests.get(addr, params=params, timeout=10)
    except requests.Timeout as _:
        logger.warn('API call timeout.')
        return JsonResponse({"msg": "timeout.", 'code': 1})
    except requests.exceptions.MissingSchema as _:
        logger.warn('')
        return JsonResponse({"msg": "Schema http/https empty.", 'code': 1})
    except requests.exceptions.InvalidURL as _:
        logger.warn('API call InvalidURL')
        return JsonResponse({"msg": "InvalidURL.", 'code': 1})
    except requests.exceptions.InvalidSchema as _:
        logger.warn('API call InvalidSchema')
        return JsonResponse({"msg": "InvalidSchema.", 'code': 1})
    except requests.exceptions.TooManyRedirects as _:
        logger.warn('API call TooManyRedirects')
        return JsonResponse({"msg": "TooManyRedirects.", 'code': 1})
    except requests.RequestException as _:
        logger.warn('API call RequestException')
        return JsonResponse({"msg": "RequestException.", 'code': 1})
    except Exception as _:
        logger.warn('API call Unknown Error')
        return JsonResponse({"msg": "Unknown Error.", 'code': 1})
    print(rsp.status_code)
    if rsp.status_code > 299 or rsp.status_code < 200:
        logger.warn('API call return error code')
        return JsonResponse({"msg": "API call return [%d]" % rsp.status_code,
                             'code': 1})
    return JsonResponse({"msg": "OK", "code": 0})


@login_required
def user_settings(request):
    c = {}
    if request.method == 'GET':
        return render_to_response('web/user_settings.html',
                                  c, RequestContext(request))
    password = request.POST.get("password")
    confirm_pwd = request.POST.get("password_confirm")
    if password != confirm_pwd:
        logger.info("修改密码时，前后不一致")
        return HttpResponseBadRequest('''
        <script>
            alert("密码修改失败，密码不一致");
            window.location.href='';
        </script>
        ''')
    password = hashlib.md5(password).hexdigest()
    request.user.set_password(password)
    request.user.save()
    logout(request)
    return HttpResponse('''
    <script>
        alert("密码修改成功，请使用新密码登录");
        window.location.href='/web/';
    </script>
    ''')


def calculate_reset_pwd_hash(timestamp, email):
    secret_key = settings.SECRET_KEY
    return md5(''.join([timestamp, email, secret_key]))


def short_url(url):
    logger.info(u'使用新浪短网址服务 %s', url)
    api_url = 'http://api.weibo.com/2/short_url/shorten.json?'
    'source=5786724301&url_long=%s' % (urllib2.quote(url))
    rsp = requests.get(api_url)
    if rsp.status_code != 200:
        logger.error(u'新浪短网址服务出错')
        return None
    obj = rsp.json()
    return obj['urls'][0]['url_short']


def send_reset_pwd_mail(url_prefix, email):
    timestamp = str(int(time.time()))
    hash_str = calculate_reset_pwd_hash(timestamp, email)
    reset_pwd_params = {
        'email': email,
        'hash': hash_str,
        'timestamp': timestamp
    }
    reset_pwd_url = "%s?%s" % (url_prefix, urllib.urlencode(reset_pwd_params))
    '''
    shorted_url = short_url(reset_pwd_url)
    if not shorted_url:
        logger.warn(u'短网址出错，无法发送邮件')
        return False
    '''
    html = (u"您可以通过点击邮件中的链接来重置您的登录密码，链接在两小时内有效，"
            u"You can click this url to reset your password "
            u"within two hours: %s" % reset_pwd_url)
    logger.info(u'密码重置 %s', html)
    mailobj = {
        "from": "espush robot <robot@email.espush.cn>",
        "to": email,
        "subject": "reset your espush password",
        "text": html
    }
    r = redis.Redis(host='localhost')
    r.lpush('queue.mail', json.dumps(mailobj))


def pwd_forgot(request):
    if request.method == 'GET':
        return render_to_response("webv2/forgot.html",
                                  {}, RequestContext(request))
    # POST
    email = request.POST.get('email')
    if not email:
        logger.warn(u'邮箱地址未输入')
        return HttpResponseRedirect(reverse('webv2_forgot'))
    code = request.POST.get('code')
    if not code:
        logger.warn(u'验证码未输入')
        return HttpResponseRedirect(reverse('webv2_forgot'))
    code = code.lower()
    true_code = request.session.get('identify_code')
    logger.info(u'重置密码 email: [%s], code: [%s], [%s]' %
                (email, code, true_code))
    if code != true_code:
        return HttpResponse("""
        <script>
            alert("验证码错误");
            window.location.href='';
        </script>
        """)
    users = User.objects.filter(email=email, stat='OK')
    if not users:
        logger.warn(u'未注册用户重置密码请求，显示成功即可')
        return HttpResponseBadRequest("""
        <script>
            alert("用户尚未注册，请直接注册新用户即可");
            window.location.href='/webv2/register/';
        </script>
        """)
    send_reset_pwd_mail("https://espush.cn/webv2/reset_pwd/", email)
    return HttpResponse("""
    <script>
        alert("密码重置邮件已发送，请尽快完成");
        window.location.href='/webv2/login/';
    </script>
    """)


_letter_cases = "abcdefghjkmnpqrstuvwxy"  # 小写字母，去除可能干扰的i，l，o，z
_upper_cases = _letter_cases.upper()  # 大写字母
_numbers = ''.join(map(str, range(3, 10)))  # 数字
init_chars = ''.join((_letter_cases, _upper_cases, _numbers))


def create_validate_code(size=(120, 30),
                         chars=init_chars,
                         img_type="GIF",
                         mode="RGB",
                         bg_color=(255, 255, 255),
                         fg_color=(0, 0, 255),
                         font_size=20,
                         font_type="ae_AlArabiya.ttf",
                         length=4,
                         draw_lines=True,
                         n_line=(1, 2),
                         draw_points=True,
                         point_chance=2):
    '''
    @todo: 生成验证码图片
    @param size: 图片的大小，格式（宽，高），默认为(120, 30)
    @param chars: 允许的字符集合，格式字符串
    @param img_type: 图片保存的格式，默认为GIF，可选的为GIF，JPEG，TIFF，PNG
    @param mode: 图片模式，默认为RGB
    @param bg_color: 背景颜色，默认为白色
    @param fg_color: 前景色，验证码字符颜色，默认为蓝色#0000FF
    @param font_size: 验证码字体大小
    @param font_type: 验证码字体，默认为 ae_AlArabiya.ttf
    @param length: 验证码字符个数
    @param draw_lines: 是否划干扰线
    @param n_lines: 干扰线的条数范围，格式元组，默认为(1, 2)，只有draw_lines为True时有效
    @param draw_points: 是否画干扰点
    @param point_chance: 干扰点出现的概率，大小范围[0, 100]
    @return: [0]: PIL Image实例
    @return: [1]: 验证码图片中的字符串
    '''

    width, height = size  # 宽， 高
    img = Image.new(mode, size, bg_color)  # 创建图形
    draw = ImageDraw.Draw(img)  # 创建画笔

    def get_chars():
        '''生成给定长度的字符串，返回列表格式'''
        return random.sample(chars, length)

    def create_lines():
        '''绘制干扰线'''
        line_num = random.randint(*n_line)  # 干扰线条数

        for _ in range(line_num):
            # 起始点
            begin = (random.randint(0, size[0]), random.randint(0, size[1]))
            # 结束点
            end = (random.randint(0, size[0]), random.randint(0, size[1]))
            draw.line([begin, end], fill=(0, 0, 0))

    def create_points():
        '''绘制干扰点'''
        chance = min(100, max(0, int(point_chance)))  # 大小限制在[0, 100]

        for w in xrange(width):
            for h in xrange(height):
                tmp = random.randint(0, 100)
                if tmp > 100 - chance:
                    draw.point((w, h), fill=(0, 0, 0))

    def create_strs():
        '''绘制验证码字符'''
        c_chars = get_chars()
        strs = ' %s ' % ' '.join(c_chars)  # 每个字符前后以空格隔开

        font = ImageFont.truetype(font_type, font_size)
        font_width, font_height = font.getsize(strs)

        draw.text(((width - font_width) / 3, (height - font_height) / 3),
                  strs, font=font, fill=fg_color)

        return ''.join(c_chars)

    if draw_lines:
        create_lines()
    if draw_points:
        create_points()
    strs = create_strs()

    # 图形扭曲参数
    params = [1 - float(random.randint(1, 2)) / 100,
              0,
              0,
              0,
              1 - float(random.randint(1, 10)) / 100,
              float(random.randint(1, 2)) / 500,
              0.001,
              float(random.randint(1, 2)) / 500
              ]
    img = img.transform(size, Image.PERSPECTIVE, params)  # 创建扭曲

    img = img.filter(ImageFilter.EDGE_ENHANCE_MORE)  # 滤镜，边界加强（阈值更大）

    return img, strs


def identify_image(request):
    if request.method == 'GET':
        font_path = os.path.join(settings.BASE_DIR,
                                 'resources/fonts',
                                 settings.IDENTIFY_IMAGE_FONTS)
        img, code = create_validate_code(font_type=font_path)
        stream = StringIO()
        img.save(stream, "png")
        request.session['identify_code'] = code.lower()
        return HttpResponse(stream.getvalue(), "image/png")


def reset_pwd(request):
    context = {}
    hash_str = request.GET.get('hash')
    if not hash_str:
        logger.info(u'用户密码重置，GET请求中缺失hash参数')
        return HttpResponseRedirect("/")
    email = request.GET.get('email')
    if not email:
        logger.info(u'用户密码重置，GET请求中缺失 email 参数')
        return HttpResponseRedirect("/")
    users = User.objects.filter(email=email, stat='OK')
    if not users:
        logger.warn(u'用户密码重置请求，但未找到此用户')
        return HttpResponseRedirect("/")
    user = users[0]
    context['email'] = email
    timestamp = request.GET.get('timestamp')
    if not timestamp:
        logger.info(u'用户密码重置，GET请求中缺失 timestamp 参数')
        return HttpResponseRedirect("/")
    timestamp = to_int(timestamp)
    if not timestamp:
        logger.info(u'用户密码重置，GET请求中, timestamp参数错误，只能为数字')
        return HttpResponseRedirect("/")
    '''
    now = int(time.time())
    if now - timestamp > 3600 * 2:
        logger.info(u'重置密码请求链接已失效')
        return HttpResponseBadRequest("""
        <script>
            alert("重置请求链接已失效，请重试。");
            window.location.href='/web/forgot/';
        </script>
        """)
    '''
    if request.method == 'GET':
        return render_to_response("webv2/reset_pwd.html",
                                  context, RequestContext(request))
    # POST, reset password
    password = request.POST.get("password")
    confirm_pwd = request.POST.get("password_confirm")
    if password != confirm_pwd:
        logger.info("修改密码时，前后不一致")
        return HttpResponseBadRequest('''
        <script>
            alert("密码修改失败，密码不一致");
            window.location.href='';
        </script>
        ''')
    password = hashlib.md5(password).hexdigest()
    user.set_password(password)
    user.save()
    return HttpResponse('''
    <script>
        alert("密码重置成功，请使用新密码登录");
        window.location.href='/web/';
    </script>
    ''')


@login_required
def reboot_dev(request, _chip):
    chipid = to_int(_chip)
    url = ('http://%s/_push_data?dev=%d&msgtype=%d' %
           (settings.SOCK_SERVER, chipid, 0x12))
    try:
        rsp = requests.post(url, timeout=5)
        if rsp.status_code != 200:
            logger.warn(u'服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn(u'服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    return JsonResponse({"result": rsp.content[10:]})


@require_POST
@csrf_exempt
@login_required
def uart_stream_push(request, _chip):
    body = request.POST.get('msg')
    if not body:
        logger.warn(u'数据不可为空')
        return HttpResponseBadRequest({"msg": "uart trans not be empty."})
    if isinstance(body, unicode):
        body = body.encode('utf-8')
    chipid = to_int(_chip)
    url = ('http://%s/_push_data?dev=%d&msgtype=%d' %
           (settings.SOCK_SERVER, chipid, 0x22))
    try:
        rsp = requests.post(url, data=body, timeout=5)
        if rsp.status_code != 200:
            logger.warn(u'服务端错误')
            return JsonResponse({'msg': "服务端错误"}, status=502)
    except requests.Timeout as _:
        logger.warn(u'服务端超时')
        return JsonResponse({'msg': "服务端超时"}, status=504)
    return JsonResponse({"result": rsp.content[10:]})


def find_device(appid, chipid, userobj):
    assert(isinstance(appid, (int, long)))
    assert(isinstance(chipid, (int, long)))
    if not appid or not chipid:
        logger.warn(u'错误，未指定appid 或 chipid')
        raise ArgumentError(u"设备类别ID或设备编号错误 [%d], [%d]" % (appid, chipid))
    try:
        app = App.objects.get(id=appid, user=userobj)
    except App.DoesNotExist as _:
        logger.warn(u'设备不存在 app %d, chip %d', appid, chipid)
        raise AppNotFoundExp(u"不存在此 设备类别")
    except App.MultipleObjectsReturned as _:
        logger.error(u'设备存在多条记录 app %d, chip %d', appid, chipid)
        raise MultiAppFoundExp(u'设备类别出错')
    devobjs = Device.objects.filter(app=app, chip=chipid)
    if not devobjs:
        logger.warn(u'未找到属于指定用户的设备')
        raise DeviceNotFoundExp(u'未找到设备 %d' % chipid)
    if len(devobjs) >= 2:
        logger.warn(u'设备表中设备记录错误 %d, %d' % (appid, chipid))
        raise MultiDeviceFoundExp(u'设备类别出错 %d, %d' % (appid, chipid))
    return devobjs[0]


@login_required
@csrf_exempt
@ajax_return
def nodemcu_editor(request, _appid, _chipid):
    appid = to_int(_appid)
    chipid = to_int(_chipid)
    find_device(appid, chipid, request.user)
    if request.method == 'GET':
        context = {}
        return render_to_response('webv2/luaeditor.html',
                                  context, RequestContext(request))
    elif request.method == 'POST':
        exec_type = request.POST.get('exec_type')
        content = request.POST.get('content')
        if exec_type not in ['execute_code',
                             'write_execute_board',
                             'write_board']:
            logger.warn(u'执行类型错误 %s' % exec_type)
            return JsonResponse({u'msg': u'error exec_type'}, status=400)
        if len(content) > 4000:
            logger.warn(u'代码行数超出限制')
            return JsonResponse({u'msg': u'too large.'}, status=400)
        exec_maps = {
            'execute_code': 1,
            'write_execute_board': 2,
            'write_board': 3
        }
        ext_msg_type = 0x26
        lua_editor_msg_type = 0x02
        body = chr(lua_editor_msg_type) + chr(exec_maps[exec_type]) + content
        _ = common_cmd_push_single_dev(chipid, ext_msg_type, body)
        return JsonResponse({u'msg': u'OK'})


@login_required
def invoice(request):
    context = {}
    return render_to_response('webv2/invoice.html',
                              context, RequestContext(request))


@login_required
def iocontrol(request):
    context = {}
    apps = App.objects.filter(user=request.user, stat='OK')
    try:
        devs = get_user_online_devices([app.id for app in apps])
    except GatewayTimeoutError as _:
        logger.warn('网关服务器调用超时')
        devs = []
    except GatewayCallError as _:
        logger.warn('网关服务器调用失败')
        devs = []
    logger.info('IO-Control 在线设备数: [%d]', len(devs))
    context['devs'] = devs
    return render_to_response('webv2/iocontrol.html',
                              context, RequestContext(request))


@login_required
@csrf_exempt
def timertask(request):
    if request.method == 'GET':
        context = {}
        tasks = TimerTaskRule.objects.filter(user=request.user, stat='VALID')
        context['tasks'] = tasks
        return render_to_response('webv2/timertask.html',
                                  context, RequestContext(request))
    elif request.method == 'POST':
        pin = to_int(request.POST.get('pin'))
        if pin is None:
            logger.warn('定时任务参数中，引脚值必须为数字')
            return HttpResponseBadRequest('引脚值必须为数字')
        edge = request.POST.get('edge')
        if edge not in ['0', '1']:
            logger.warn('定时任务参数中，电平信号错误 %s', edge)
            return HttpResponseBadRequest('电平信号错误')
        dest_type = request.POST.get('category')
        if dest_type not in ['dev', 'app']:
            logger.warn('定时任务参数中，目标设备类型错误')
            return HttpResponseBadRequest('目标设备类型错误')
        chipid = ''
        if dest_type == 'dev':
            chipid = request.POST.get('chipid')
            if not chipid:
                logger.warn('定时任务参数，设备编号错误')
                return HttpResponseBadRequest('设备编号错误')
        appid = request.POST.get('appid')
        if not appid:
            logger.warn('定时任务参数，设备类型编码错误')
            return HttpResponseBadRequest('设备类型编码错误')
        cron_type = request.POST.get('cron_type')
        if not cron_type:
            logger.warn('定时任务参数，任务周期参数类型错误')
            return HttpResponseBadRequest('任务周期参数类型错误')
        cron_val = request.POST.get('cron_val')
        if not cron_val:
            logger.warn('定时任务参数，任务周期参数值错误')
            return HttpResponseBadRequest('任务周期参数值错误')
        try:
            jobid = new_task_backend(cron_type, cron_val, pin, edge)
        except EspushException as e:
            logger.warn(e.message)
            return HttpResponseServerError(e.message)
        now = datetime.datetime.now()
        jobobj = TimerTaskRule(
            taskid=jobid,
            category=cron_type.upper(),
            cron_val=cron_val,
            dest_type=dest_type,
            dest_appid=appid,
            dest_chipid=chipid,
            pin=pin,
            edge=edge,
            create_time=now,
            user=request.user,
            stat='VALID'
        )
        jobobj.save()
        return HttpResponse("OK")


@login_required
@csrf_exempt
def timertask_remove(request, rid):
    try:
        ruleobj = TimerTaskRule.objects.get(id=rid,
                                            stat='VALID',
                                            user=request.user)
    except TimerTaskRule.DoesNotExist:
        return HttpResponseNotAllowed('未找到指定的定时任务')
    ruleobj.stat = 'DELETED'
    '过期的一次性任务，直接删除'
    if ruleobj.category == 'DATE':
        task_date = datetime.datetime.strptime(ruleobj.cron_val,
                                               '%Y-%m-%d %H:%M')
        now = datetime.datetime.now()
        if now >= task_date:
            ruleobj.save()
            return HttpResponse('任务 [%s] 已被删除' % ruleobj.taskid)
    '否则需要同步apscheduler的数据库'
    try:
        remove_task(ruleobj.taskid)
    except EspushException as e:
        logger.warn(e.message)
        return HttpResponseServerError('任务删除失败 ')
    ruleobj.save()
    return HttpResponse('任务 [%s] 已被删除' % ruleobj.taskid)


@login_required
def app_list(request):
    apps = App.objects.filter(user=request.user, stat='OK')
    out = [{'appid': el.id, 'name': el.app_name} for el in apps]
    return JsonResponse(out, safe=False)


@login_required
def crontab(request):
    context = {}
    return render_to_response('webv2/crontab.html',
                              context, RequestContext(request))


@login_required
def tasklist(request):
    rules = request.user.timertaskrule_set.filter(stat='VALID')
    taskarr = [{
                'id': rule.id,
                'name': rule.name,
                'appname': rule.app.app_name,
                'create_time': rule.create_time.strftime("%Y-%m-%d %H:%M:%S"),
                'cronval': rule.cronval,
                'pin': rule.pin,
                'edge': rule.edge
                } for rule in rules]
    return JsonResponse(taskarr, safe=False)


@login_required
@csrf_exempt
def task_remove(request, taskid):
    try:
        ruleobj = request.user.timertaskrule_set.get(id=taskid, stat='VALID')
    except TimerTaskRule.DoesNotExist:
        return HttpResponseNotFound('未找到指定的任务')
    if request.method == 'DELETE':
        url = settings.CRONTAB_RPC_URL + 'del'
        rsp = requests.post(url, data={'jobid': ruleobj.taskid})
        if rsp.status_code != 200:
            logger.warn('删除计时器请求错误 %d %s', rsp.status_code, rsp.content)
            return HttpResponseBadRequest('删除出错 %s' % rsp.content)
        else:
            ruleobj.stat = 'DELETED'
            ruleobj.save()
            return HttpResponse('ok')
    return HttpResponseNotAllowed('unimplement')


@login_required
def tasklog(request):
    logs = request.user.tasklog_set.all()
    offset = request.GET.get('offset')
    count = request.GET.get('count')
    offset = to_int(offset)
    if not offset:
        offset = 0
    count = to_int(count)
    if not count:
        count = 10
    logs = logs[offset: offset + count]
    logarr = [{
               'id': log.id,
               'rulename': log.rule.name,
               'exec_time': log.exec_time,
               'result': log.result,
               'note': log.note
               } for log in logs]
    return JsonResponse(logarr, safe=False)


def check_args_none(**kwargs):
    for key in kwargs:
        if not kwargs[key]:
            return key
    return None


def deserialize_date(strin):
    try:
        return datetime.datetime.strptime(strin, '%Y-%m-%d %H:%M')
    except ValueError as _:
        return None


@login_required
@csrf_exempt
@reqjson
def newtask(request):
    name = request.reqjson.get('name')
    appid = request.reqjson.get('appid')
    crontype = request.reqjson.get('crontype')
    pin = request.reqjson.get('pin')
    edge = request.reqjson.get('edge')
    cronval = request.reqjson.get('cronval')
    begin_date_s = request.reqjson.get('begin_date')
    end_date_s = request.reqjson.get('end_date')
    chk_args = check_args_none(name=name, appid=appid,
                               crontype=crontype, cronval=cronval)
    now = datetime.datetime.now()
    if chk_args:
        return HttpResponseBadRequest('参数错误' + chk_args)
    if to_int(pin) is None:
        logger.warn('GPIO PIN脚只支持数字')
        return HttpResponseBadRequest('PIN引脚值错误')
    if edge not in [0, 1]:
        logger.warn('GPIO操作只支持开关')
        return HttpResponseBadRequest('参数错误 edge 状态值错误')
    if begin_date_s:
        begin_date = deserialize_date(begin_date_s)
    else:
        begin_date = now
    if not begin_date:
        return HttpResponseBadRequest('开始日期格式错误')
    if end_date_s:
        end_date = deserialize_date(end_date_s)
        if begin_date >= end_date:
            return HttpResponseBadRequest('开始日期晚于结束日期')
    else:
        end_date = datetime.datetime(9999, 9, 9, 9, 9, 9, 9)
        end_date_s = end_date.strftime('%Y-%m-%d %H:%M')
    crontype = crontype.upper()
    if crontype == 'INTERVAL':
        cron_seconds = to_int(cronval)
        if cron_seconds is None:
            logger.warn('选择循环，循环周期必须为数字')
            return HttpResponseBadRequest('循环周期必须为数字')
        if cron_seconds < 30:
            return HttpResponseBadRequest('循环周期不得小于30秒')
    appobj = request.user.app_set.get(id=appid)
    now = datetime.datetime.now()
    # add to db
    rule = TimerTaskRule(
        name=name,
        taskid='ING',
        crontype=crontype,
        cronval=cronval,
        app=appobj,
        pin=pin,
        edge=edge,
        create_time=now,
        user=request.user,
        begin_date=begin_date,
        end_date=end_date,
        stat='INVALID'
    )
    rule.save()
    url = settings.CRONTAB_RPC_URL + 'add'
    data = {
        'ruleid': rule.id,
        'crontype': crontype,
        'appid': appid,
        'cronval': cronval,
        'pin': pin,
        'edge': edge,
        'begin_date': begin_date_s,
        'end_date': end_date_s
    }
    rsp = requests.post(url, data=data)
    if rsp.status_code != 200:
        logger.warn('计划任务新建失败 %s', rsp.content)
        return HttpResponseBadRequest('失败 %s' % (rsp.content))
    rspobj = rsp.json()
    if 'jobid' not in rspobj:
        logger.warn('计划任务新建失败，未找到JOBID')
        return HttpResponseBadRequest('失败 未找到JOBID')
    jobid = rspobj.get('jobid')
    rule.taskid = jobid
    rule.stat = 'VALID'
    rule.save()
    return JsonResponse({
                         'id': rule.id,
                         'create_time': now.strftime("%Y-%m-%d %H:%M:%S")
                         })


@csrf_exempt
def appendlog(request):
    pass


@login_required
def get_timestamp(request):
    return JsonResponse({'timestamp': int(time.time())})


def write_upload_file_trunk(upfile, outfilename):
    with open(outfilename, 'wb') as fout:
        for chunk in upfile.chunks():
            fout.write(chunk)


@admin_required
@login_required
def admin_rom_view(request):
    ctx = {}
    if request.method == 'GET':
        ctx['roms'] = EspRom.objects.all()
        return render_to_response('webv2/admin/roms.html', ctx, RequestContext(request))
    elif request.method == 'POST':
        romname = request.POST.get('romname')
        romver = request.POST.get('version')
        realname = request.POST.get('realname')
        outpath = settings.ROMS_UPLOAD_DIR
        if not os.path.exists(outpath):
            os.mkdir(outpath)
        now = datetime.datetime.now()
        timestamp = now.strftime('%Y%m%d%H%M%S')
        if not romname or not romver or not realname:
            return HttpResponseBadRequest("请求参数出错")
        if 'romfile' not in request.FILES:
            return HttpResponseBadRequest("固件文件不能为空")
        romfile = request.FILES['romfile']
        romfilename = '%s_rom.zip' % timestamp
        write_upload_file_trunk(romfile, os.path.join(outpath, romfilename))
        romdbobj = EspRom(
            name=romname,
            realname=realname,
            version=romver,
            rom=romfilename,
            upload_time=now,
            stat='VALID'
        )
        if 'user1bin' in request.FILES:
            user1bin = request.FILES['user1bin']
            user1filename = '%s_user1.bin' % timestamp
            write_upload_file_trunk(user1bin, os.path.join(outpath, user1filename))
            romdbobj.user1 = user1filename
        if 'user2bin' in request.FILES:
            user2bin = request.FILES['user2bin']
            user2filename = '%s_user2.bin' % timestamp
            write_upload_file_trunk(user2bin, os.path.join(outpath, user2filename))
            romdbobj.user2 = user2filename
        romdbobj.save()
        return HttpResponseRedirect(reverse('webv2_admin_roms'))


@admin_required
@login_required
def admin_down_romfile(request, romid):
    outpath = settings.ROMS_UPLOAD_DIR
    name = request.GET.get('type')
    if not name:
        return HttpResponseBadRequest('请求参数错误')
    try:
        romdbobj = EspRom.objects.get(id=romid, stat='VALID')
    except EspRom.DoesNotExist as _:
        return HttpResponseNotFound('找不到指定的资源')
    if name == 'rom':
        return make_down_available_rsp(outpath, romdbobj.rom)
    elif name == 'user1':
        if romdbobj.user1:
            return make_down_available_rsp(outpath, romdbobj.user1)
    elif name == 'user2':
        if romdbobj.user2:
            return make_down_available_rsp(outpath, romdbobj.user2)
    else:
        return HttpResponseBadRequest("请求参数不合法！")
    return HttpResponseNotFound("未找到需要的文件")


@admin_required
@login_required
def admin_online_devices(request):
    ctx = {}
    url = 'http://%s/all_online' % settings.SOCK_SERVER
    content = """
    <script>alert("%s");window.history.back();</script>
    """
    try:
        rsp = requests.get(url)
        if rsp.status_code != 200:
            logger.warn(u'网关返回错误，数据可能推送失败')
            return HttpResponse(content % "网关返回错误", status=504)
    except requests.Timeout as _:
        logger.error(u'网关请求超时')
        return HttpResponse(content % "网关请求超时", status=504)
    except IOError as _:
        logger.error(u'请求失败')
        return HttpResponse(content % "请求网关失败, IOError", status=504)
    devices = rsp.json()
    for dev in devices:
        if 'chipid' not in dev or 'appid' not in dev:
            continue
        try:
            dev['app'] = App.objects.get(id=dev['appid'])
        except App.DoesNotExist as _:
            continue
    ctx['online_devs'] = devices
    return render_to_response("webv2/admin/devices.html", ctx, RequestContext(request))


@admin_required
@login_required
def admin_users(request):
    limit = 20
    ctx = {}
    records = User.objects.order_by("-last_login")
    paginator = Paginator(records, limit)
    page = request.GET.get('page')
    pagenum = to_int(page)
    if not page:
        return HttpResponseRedirect("?page=1")
    try:
        ctx['records'] = paginator.page(pagenum)
    except PageNotAnInteger:
        return HttpResponseRedirect("?page=1")
    except EmptyPage:
        return HttpResponseRedirect("?page=%d" % (paginator.num_pages))
    return render_to_response('webv2/admin/users.html', ctx, RequestContext(request))


@admin_required
@login_required
def admin_wechat_users(request):
    limit = 20
    ctx = {}
    records = WechatUser.objects.filter(stat='VALID').order_by("-id")
    paginator = Paginator(records, limit)
    page = request.GET.get('page')
    pagenum = to_int(page)
    if not page:
        return HttpResponseRedirect("?page=1")
    try:
        page_records = paginator.page(pagenum)
    except PageNotAnInteger:
        return HttpResponseRedirect("?page=1")
    except EmptyPage:
        return HttpResponseRedirect("?page=%d" % (paginator.num_pages))
    page_users = [user for user in page_records]
    userInfos = wechat_userinfo_batchget([user.openid for user in page_users])
    for userObj in page_users:
        userObj.info = userInfos[userObj.openid]
    ctx['records'] = page_records
    return render_to_response('webv2/admin/wechat_users.html', ctx, RequestContext(request))


@admin_required
@login_required
def admin_crontabs(request):
    ctx = {}
    ctx['records'] = TimerTaskRule.objects.exclude(stat='DELETED').order_by("-id")
    return render_to_response('webv2/admin/crontabs.html', ctx, RequestContext(request))


@admin_required
@login_required
def admin_apps(request):
    limit = 20
    ctx = {}
    records = App.objects.exclude(stat='DELETED').order_by("-id")
    paginator = Paginator(records, limit)
    page = request.GET.get('page')
    pagenum = to_int(page)
    if not page:
        return HttpResponseRedirect("?page=1")
    try:
        ctx['records'] = paginator.page(pagenum)
    except PageNotAnInteger:
        return HttpResponseRedirect("?page=1")
    except EmptyPage:
        return HttpResponseRedirect("?page=%d" % (paginator.num_pages))
    return render_to_response('webv2/admin/apps.html', ctx, RequestContext(request))
