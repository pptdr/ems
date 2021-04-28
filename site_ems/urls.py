from django.contrib import admin
from django.urls import path
from django.conf.urls import url, include
from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView,PasswordResetCompleteView
from django.conf.urls import handler404, handler500, handler403, handler400
from django.contrib.auth import views as auth_views
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    url(r'^$', views.index),
    url(r'^about$', views.about, name='about'),
    url(r'^home$', views.home, name='home'),
    url(r'^login$', views.login, name='login_page'),
    url(r'^logout/$', views.logout, name='logout'),
    url(r'^adminpage$', views.adminpage, name='adminpage'),
    url(r'^userpage$', views.userpage, name='userpage'),
    url(r'^cmp1$', views.cmp, name='cmp1'),
    path('cmp',views.cmp),
    path('show', views.show),
    path('edit/<int:id>', views.edit),
    path('update/<int:id>', views.update),
    path('delete/<int:id>', views.destroy),
    url(r'^addcompany$', views.add_company_details, name='addcompany'),

    path(r'password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='Forgot_password/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name="Forgot_password/password_reset_confirm.html"), name='password_reset_confirm'),
#    path(r'^reset/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$', auth_views.PasswordResetConfirmView.as_view(template_name="Forgot_password/password_reset_confirm.html"), name='password_reset_confirm'),
    path(r'reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='Forgot_password/password_reset_complete.html'), name='password_reset_complete'),
    path(r"password_reset", views.password_reset_request, name="password_reset"),
] + static(settings.MEDIA_URL, document_root= settings.MEDIA_ROOT)

handler404 = 'site_ems.views.error_404'
handler500 = 'site_ems.views.server_error'
handler403 = 'site_ems.views.error_403'
handler400 = 'site_ems.views.error_400'


