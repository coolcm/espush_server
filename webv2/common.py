#!/usr/bin/env python
# encoding: utf-8

from __future__ import unicode_literals
from __future__ import print_function


import requests
import logging

from django.conf import settings
import json
from django.http.response import HttpResponseBadRequest, HttpResponseNotFound,\
    HttpResponseServerError

from contrib.exceptions import GatewayApiError, GatewayTimeoutError, GatewayCallError, ArgumentError, AppNotFoundExp, \
    DeviceNotFoundExp, MultiDeviceFoundExp, MultiAppFoundExp

logger = logging.getLogger('espush')


def common_cmd_push_single_dev(chipid, msgtype, content, timeout=8):
    assert(isinstance(chipid, (int, long)))
    url = ('http://%s/_push_data?dev=%d&msgtype=%d'
           % (settings.SOCK_SERVER, chipid, msgtype))
    # 发出网络请求, 推送数据
    try:
        rsp = requests.post(url, timeout=8, data=content)
        if rsp.status_code != 200:
            logger.warn(u'[%d] 网关接口返回非200 [%d], [%s]',
                        msgtype, rsp.status_code, rsp.content)
            raise GatewayApiError(u'Gateway server returned [%d]' %
                                  rsp.status_code)
        return rsp.content
    except requests.Timeout as _:
        logger.error(u'[%d] 网关请求超时', msgtype)
        raise GatewayTimeoutError(u'网关请求超时')
    except IOError as _:
        logger.error(u'[%d] 请求失败', msgtype)
        raise GatewayCallError(u'请求网关失败')


def ajax_return(fn):
    def _wrapper(request, *args, **kwargs):
        try:
            return fn(request, *args, **kwargs)
        except ArgumentError as e:
            obj = {u'msg': e.message}
            return HttpResponseBadRequest(json.dumps(obj))
        except AppNotFoundExp as e:
            obj = {u'msg': e.message}
            return HttpResponseNotFound(json.dumps(obj))
        except DeviceNotFoundExp as e:
            obj = {u'msg': e.message}
            return HttpResponseNotFound(json.dumps(obj))
        except MultiDeviceFoundExp as e:
            obj = {u'msg': e.message}
            return HttpResponseServerError(json.dumps(obj))
        except MultiAppFoundExp as e:
            obj = {u'msg': e.message}
            return HttpResponseServerError(json.dumps(obj))
        except GatewayApiError as e:
            obj = {u'msg': e.message}
            return HttpResponseServerError(json.dumps(obj))
        except GatewayTimeoutError as e:
            obj = {u'msg': e.message}
            return HttpResponseServerError(json.dumps(obj))
        except GatewayCallError as e:
            obj = {u'msg': e.message}
            return HttpResponseServerError(json.dumps(obj))
    return _wrapper
