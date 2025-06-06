from rest_framework import serializers
from .models import User, ChatHistory
from django.contrib.auth.hashers import make_password

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'email']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)

class ChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatHistory
        fields = ['user_message', 'bot_response', 'timestamp']
