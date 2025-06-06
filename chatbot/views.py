from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from django.conf import settings
import requests
from django.db.models.functions import TruncDate
from django.db.models import OuterRef, Subquery, F
from .models import ChatHistory
from .serializers import RegisterSerializer, ChatSerializer
from django.shortcuts import render
from django.db import DatabaseError
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db.models import Q
from django.utils.dateparse import parse_date


def login_page(request):
    return render(request, 'chatbot/login.html')  # Ensure this template exists


def register_page(request):
    return render(request, 'chatbot/register.html')  # Ensure this template exists


def chat_page(request):
    return render(request, 'chatbot/chat.html')  # Ensure this template exists


# -------------------------------
# Registration View
# -------------------------------
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        email = request.data.get("email")

        if not username or not password:
            return Response(
                {'error': 'Username and password are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if User.objects.filter(username=username).exists():
            return Response(
                {'error': 'Username already exists.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = User.objects.create(
            username=username,
            password=make_password(password),
            email=email
        )
        refresh = RefreshToken.for_user(user)
        return Response({
            'message': 'User registered successfully.',
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_201_CREATED)


# -------------------------------
# Login View
# -------------------------------
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response(
                {'error': 'Please provide username and password.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(username=username, password=password)
        if user is None:
            return Response(
                {'error': 'Invalid credentials.'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        refresh = RefreshToken.for_user(user)
        return Response({
            'message': 'Login successful.',
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)


# -------------------------------
# Logout View
# -------------------------------
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            token = RefreshToken(refresh_token)
            token.blacklist()  # blacklist the refresh token
            return Response(
                {"message": "Logout successful."},
                status=status.HTTP_205_RESET_CONTENT
            )
        except Exception as e:
            return Response(
                {"error": f"Invalid token or token missing. {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


# -------------------------------
# ChatBot View with CSRF Exempt
# -------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class ChatBotView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_input = request.data.get("message")
        if not user_input:
            return Response(
                {"error": "Message is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            url = "https://openrouter.ai/api/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
                "Content-Type": "application/json"
            }
            data = {
                "model": "mistralai/mistral-7b-instruct",
                "messages": [{"role": "user", "content": user_input}]
            }

            response = requests.post(url, json=data, headers=headers)

            if response.status_code != 200:
                return Response({
                    "error": f"Error from OpenRouter: {response.status_code} - {response.json()}"
                }, status=response.status_code)

            bot_response = response.json()['choices'][0]['message']['content']

            chat = ChatHistory.objects.create(
                user=request.user,
                user_message=user_input,
                bot_response=bot_response
            )

            return Response({
                "user_message": user_input,
                "bot_response": bot_response,
                "timestamp": chat.timestamp
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# -------------------------------
# Daily Latest Bot Response View
# -------------------------------
class DailyLatestBotResponseView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        try:
            # Subquery to get latest chat ID per day using timestamp__date
            latest_ids = ChatHistory.objects.filter(
                user=user,
                timestamp__date=OuterRef('timestamp__date')
            ).order_by('-timestamp').values('id')[:1]

            # Filter to only keep latest per day
            latest_chats = ChatHistory.objects.annotate(
                latest_id=Subquery(latest_ids)
            ).filter(
                user=user,
                id=F('latest_id')
            ).values('id', 'bot_response', 'timestamp').order_by('-timestamp')

            if not latest_chats:
                return Response(
                    {"message": "No chat history found for this user."},
                    status=status.HTTP_204_NO_CONTENT
                )

            return Response(list(latest_chats), status=status.HTTP_200_OK)

        except DatabaseError as db_err:
            return Response(
                {"error": "Database error occurred", "details": str(db_err)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            return Response(
                {"error": "Unexpected error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ChatByDateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        date_str = request.query_params.get('date')  # Expected format: 'YYYY-MM-DD'

        if not date_str:
            return Response({"error": "Date is required in 'YYYY-MM-DD' format."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            date = parse_date(date_str)
            if not date:
                return Response({"error": "Invalid date format. Use 'YYYY-MM-DD'."}, status=status.HTTP_400_BAD_REQUEST)

            # Get all chats on that date
            chats = ChatHistory.objects.filter(
                user=user,
                timestamp__date=date
            ).values('id', 'user_message', 'bot_response', 'timestamp').order_by('timestamp')

            if not chats:
                return Response({"message": "No chats found for the specified date."}, status=status.HTTP_204_NO_CONTENT)

            return Response(list(chats), status=status.HTTP_200_OK)

        except DatabaseError as db_err:
            return Response({"error": "Database error", "details": str(db_err)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": "Unexpected error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AllUsersChatHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            chats = ChatHistory.objects.select_related('user').all().order_by('-timestamp')
            if not chats.exists():
                return Response(
                    {"message": "No chat history found."},
                    status=status.HTTP_204_NO_CONTENT
                )
            serializer = ChatSerializer(chats, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": f"Something went wrong: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            