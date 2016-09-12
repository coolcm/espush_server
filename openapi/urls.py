#!/usr/bin/env python
# encoding: utf-8

from __future__ import unicode_literals

'''

@author: Sunday
'''

from django.conf.urls import patterns, url

urlpatterns = patterns(
    'openapi.views',
    # Examples:
    # url(r'^$', 'wifi.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^$', 'index'),
    url(r'^apps/$', 'appinfo'),
    url(r'^devices/online/$', 'online_devices_list'),
    url(r'^devices/lists/$', 'online_devices_list'),
    url(r'^devices/all/$', 'all_devices_list'),
    url(r'^dev/push/message/$', 'dev_push_msg'),
    url(r'^app/push/message/$', 'app_push_msg'),
    url(r'^device/(\d+)/ota/$', 'dev_push_ota'),
    url(r'^device/(\d+)/cur_userbin/$', 'dev_userbin'),
    url(r'^device/(\d+)/is_alive/$', 'dev_is_alive'),
    url(r'^up_messages/$', 'up_messages'),
    url(r'^up_messages/dev/(\d+)/$', 'up_dev_messages'),
    url(r'^push_messages/$', 'push_messages'),
    url(r'^push_messages/dev/(\d+)/$', 'dev_push_messages'),
    url(r'^sync/(\d+)/(\d+)/$', 'sync'),
    url(r'^rt_status/(\d+)/$', 'rt_status'),
    url(r'^gpio_status/(\d+)/$', 'gpio_status'),
    url(r'^set_gpio_edge/(\d+)/(\d+)/([0,1])/$', 'set_gpio_edge'),
    url(r'^manual_refresh/(\d+)/$', 'manual_refresh'),
    url(r'^reboot/dev/(\d+)/$', 'reboot_dev'),
    url(r'^notice_api_test/$', 'notice_api_test'),
    url(r'^status/(\d+)/$', 'whether_is_online'),
    # API V2
    url(r'^v2/roms/$', 'romlist'),
    url(r'^v2/romfile/(\d+)/$', 'romfile'),
    url(r'^v2/user/login/$', 'user_login'),
    url(r'^v2/user/online/devices/$', 'user_online_devices'),
    url(r'^v2/user/apps/$', 'user_apps'),
    url(r'^v2/(\d+)/gpio/$', 'get_gpio_status'),
    url(r'^v2/(\d+)/color/(\d)/(\d+)/$', 'color_change'),
)

