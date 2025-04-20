# bank/urls.py

from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.portfolio_view, name='portfolio'),
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('stocks/', views.stock_list_view, name='stock_list'),
    path('invest/<str:ticker>/', views.invest_view, name='invest'),
    path('admin_dashboard/', views.admin_dashboard_view, name='admin_dashboard'),
    path('admin_user/<int:user_id>/', views.admin_user_detail_view, name='admin_user_detail'),
    path('admin_user_delete/<int:user_id>/', views.admin_user_delete_view, name='admin_user_delete'),
    path('admin_create_user/', views.admin_create_user_view, name='admin_create_user'),
    path('advisor/', views.advisor_view, name='advisor'),
    path('advisor_client_detail/<int:client_id>/', views.advisor_client_detail_view, name='advisor_client_detail'),
    path('advisor_message/', views.advisor_message_view, name='advisor_message'),
    path('rotate_keys/', views.rotate_keys_view, name='rotate_keys'),
    path('clear_db/', views.clear_db_view, name='clear_db'),
    path('portfolio_history/', views.portfolio_history_view, name='portfolio_history'),
    path('advisor_transaction/', views.advisor_transaction_view, name='advisor_transaction'),
    path('client_transaction/', views.client_transaction_view, name='client_transaction'),
    path('create_chat/', views.create_chat_view, name='create_chat'),
    path('chat/', views.chat_redirect_view, name='chat_redirect'),
    path('chat/<str:username>/', views.chat_detail_view, name='chat'),
    path('profile/update/', views.profile_update_view, name='profile_update'),
    path('password-reset/', auth_views.PasswordResetView.as_view(
        template_name='password_reset.html'
    ), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='password_reset_done.html'
    ), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='password_reset_confirm.html'
    ), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
        template_name='password_reset_complete.html'
    ), name='password_reset_complete'),
]
