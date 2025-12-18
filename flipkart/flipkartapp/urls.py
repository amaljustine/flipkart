from django.contrib import admin
from django.urls import path, re_path, include
from . import views


urlpatterns = [

    path('create-or-update-user', views.CreateOrUpdateUserApiView.as_view()),
    path('change-password',views.UpdateUsprepasswordApiView.as_view()),
    path('login',views.LoginApiView.as_view()),
    path('user-info',views.RetrieveUserInfoApiView.as_view()),
]