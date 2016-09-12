# -*- coding: UTF-8 -*-

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division

import os
import logging
from django.conf import settings
from django.http.response import HttpResponseNotFound, HttpResponse,\
    HttpResponseServerError, HttpResponseRedirect


logger = logging.getLogger('espush')


def favicon(request):
    base_dir = settings.BASE_DIR
    filename = 'espush.png'
    filepath = os.path.join(base_dir, 'resources/images/', filename)
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        logger.warn('favicon文件错误')
        return HttpResponseNotFound("Error, Not Found")
    types = 'image/png'
    with open(filepath, 'rb') as fout:
        rsp = HttpResponse(fout.read(), content_type=types)
        rsp['Content-Disposition'] = 'filepath=%s' % filename
        return rsp
    return HttpResponseServerError("Error, Server Error")


def avatar(request, imgid):
    return HttpResponseRedirect('https://espush.cn/avatar/%s/' % imgid)
