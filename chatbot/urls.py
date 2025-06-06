from django.urls import path
from .views import chat_page , login_page,register_page, RegisterView, LoginView, LogoutView, ChatBotView,  DailyLatestBotResponseView, ChatByDateView, AllUsersChatHistoryView

urlpatterns = [
    path('', login_page, name='login-page'),
    path('register-page/', register_page, name='register-page'),
    path('chat-page/', chat_page, name='chat-page'),   # HTML login form
   # HTML login form
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),    # API POST login
    path('logout/', LogoutView.as_view(), name='logout'),
    path('chat/', ChatBotView.as_view(), name='chat'),
    # path('chat/history/', ChatHistoryView.as_view(), name='chat-history'),
    path('chat/daily-latest/', DailyLatestBotResponseView.as_view(), name='chat-daily-latest'),
    path('api/chat-by-date/', ChatByDateView.as_view(), name='chat-by-date'),
    path('chat-history/', AllUsersChatHistoryView.as_view(), name='chat-history'),
]

