#!/usr/bin/env python
# encoding: utf-8

from __future__ import unicode_literals

'''

@author: Sunday
'''

from django.conf.urls import patterns, url

urlpatterns = patterns(
    'weixin.views',
    # Examples:
    # url(r'^$', 'wifi.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    # API 接口
    url(r'^wechat/$', 'wechat'),
    # 菜单进入的网页
    url(r'^wechat_bind_user/$', 'bind_user'),
    url(r'^bind_user_req/', 'bind_user_req'),
    url(r'^wechat_webapp/$', 'wechat_webapp'),
    url(r'^wechat_register_user/$', 'register_user'),
    url(r'^wechat_forgot/$', 'forgot'),
    url(r'^wechat_network_config/$', 'network_config'),
    url(r'^redirect/docs/', 'redirect_docs'),
    # 菜单进入网页完
    # API BEGIN
    url(r'^api/devices/online/$', 'api_devices_online'),
    url(r'^api/devices/(\d+)/pins/$', 'api_device_pins'),
    url(r'^api/devices/(\d+)/pins/(\d+)/edge/(\d)/$', 'api_device_set_pin_edge'),
    url(r'^api/devices/(\d+)/dhtvalue/$', 'api_dht_value'),
    url(r'^api/devices/(\d+)/gpio16/(\d)/$', 'api_gpio16_change'),
    # API END
)
