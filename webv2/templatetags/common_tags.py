#!/usr/bin/env python
# encoding: utf-8

from __future__ import unicode_literals
from __future__ import print_function

import datetime
from django import template
from django.core.urlresolvers import reverse, resolve


register = template.Library()


@register.simple_tag()
def is_active(request, *url_strings):
    for urlpattern in url_strings:
        if urlpattern in request.path:
            return 'active'
    return ''


@register.simple_tag
def is_active_reverse(request, *urlnames):
    for urlname in urlnames:
        if reverse(urlname) in request.path:
            return "active"
    return ""


@register.simple_tag
def is_active_resolve(request, *urlnames):
    resolver_match = resolve(request.path)
    for urlname in urlnames:
        if resolver_match.url_name == urlname:
            return "active"
    return ""


def timestamp_to_datetime(value):
    if isinstance(value, str):
        value = int(value)
    return datetime.datetime.fromtimestamp(value)


register.filter('timestamp', timestamp_to_datetime)