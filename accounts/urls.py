from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),

    path('forgotPassword/', views.forgot_password, name='forgot_password'),
    path('forgotPassword_validate/', views.forgot_password_validate,
         name='forgot_password_validate'),
    path('resetPassword/', views.reset_password, name='reset_password'),
]
