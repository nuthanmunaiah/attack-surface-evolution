from django.conf.urls import patterns, include, url

from app.views import *

urlpatterns = patterns(
    '',
    url(r'^$', RevisionListView.as_view(), name='root'),
    url(r'^revisions/$', RevisionListView.as_view(), name='revision-list'),
    url(r'^revision/(?P<pk>\d+)/functions/$', FunctionListView.as_view(),
        name='revision-detail'),
)
