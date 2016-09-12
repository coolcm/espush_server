# encoding: utf-8

from __future__ import unicode_literals

from django.conf.urls import patterns, include, url
from django.views.generic.base import RedirectView


urlpatterns = patterns(
    '',
    # Examples:
    # url(r'^$', 'wifi.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^i18n/', include('django.conf.urls.i18n')),
    url(r'^$', 'webv2.views.site_index'),
    url(r'^web/', RedirectView.as_view(url='/webv2/')),
    url(r'^webv2/', include('webv2.urls')),
    # url(r'^payment/', include('payment.urls')),
    # url(r'^admin/', include(admin.site.urls)),
    url(r'^openapi/', include('openapi.urls')),
    url(r'^weixin/', include('weixin.urls')),
    url(r'^avatar/(\w+)/$', 'wifi.views.avatar'),
    url(r'^favicon.ico$', 'wifi.views.favicon'),
)
