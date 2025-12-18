import re
from rest_framework import serializers
from flipkartapp.models import Users
from flipkart.helpers.helper import get_object_or_none, get_token_user_or_none
from django.contrib.auth.models import Permission
from django.contrib.auth.hashers import check_password

"""""create user"""

class CreateOrUpdateUserSerializer(serializers.ModelSerializer):

    user                      = serializers.IntegerField(allow_null=True, required=False)
    phonenumber               = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    # profile_image             = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    username                  = serializers.CharField(required=True)
    email                     = serializers.EmailField(required=False, allow_null=True, allow_blank=True)
    password                  = serializers.CharField(required=False)
    is_admin                  = serializers.BooleanField(default=False)
    is_staff                  = serializers.BooleanField(default=False)
    # groups                    = serializers.PrimaryKeyRelatedField(read_only=False, many=True, queryset=Group.objects.all(), required=True)

    class Meta:
        model = Users 
        fields = ['user','username','email','password','phonenumber','is_active','is_admin','is_staff']
    

    def validate(self, attrs):
        email           = attrs.get('email', '')
        user            = attrs.get('user', None)
        username        = attrs.get('username', None)
        password        = attrs.get('password', None)

        user_query_set = Users.objects.filter(email=email)
        user_object    = Users.objects.filter(username=username)

        if username is not None:
            if not re.match("^[a-zA-Z0-9._@]*$", username):
                raise serializers.ValidationError({'username':("Enter a valid Username. Only alphabets, numbers, '@', '_', and '.' are allowed.")})
        
        user_instance = None 

        if user is not None:
            user_instance = get_object_or_none(Users, pk=user)

        if user_instance not in ['',None]:
            user_query_set = user_query_set.exclude(pk=user_instance.pk)
            user_object = user_object.exclude(pk=user_instance.pk)  

        if user_object.exists():
            raise serializers.ValidationError({"username":('Username already exists!')})
        
        if user_query_set.exists():
            raise serializers.ValidationError({"email":('Email already exists!')})
        
        if password is not None and (len(password) < 8 or not any(char.isupper() for char in password) or not any(char.islower() for char in password) or not any(char.isdigit() for char in password) or not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?\'\"\\/~`' for char in password)):
            raise serializers.ValidationError({"password":('Must Contain 8 Characters, One Uppercase, One Lowercase, One Number and One Special Character')})
               

        return super().validate(attrs)
    

    def create(self,validated_data):
        password            = validated_data.get('password')
        
        instance            = Users()
        instance.set_password(password)

        instance.username            = validated_data.get('username')
        instance.email               = validated_data.get('email')
        instance.is_admin            = validated_data.get('is_admin')
        instance.is_staff            = True
        instance.save()
        return instance
    
    def update(self,instance,validated_data):

        password = validated_data.get('password','')

        instance.username = validated_data.get('username')
        instance.first_name = validated_data.get('first_name')
        instance.last_name  = validated_data.get('last_name')
        instance.email = validated_data.get('email')
        instance.phonenumber = validated_data.get('phonenumber')
        if password:
            instance.set_password(password) 

        if validated_data.get('is_active',''):
            instance.is_active = validated_data.get('is_active')
            
            
        if validated_data.get('is_admin',''):
            instance.is_admin = validated_data.get('is_admin')
            
        if validated_data.get('is_staff',''):
            instance.is_staff = validated_data.get('is_staff')
        
        instance.save()

        return instance



"""""change password"""


class ChangePasswordSerializer(serializers.Serializer):

    user                = serializers.IntegerField(required=True)
    current_password    = serializers.CharField(required=True)
    new_password        = serializers.CharField(required=True)

    def validate(self, attrs):
        current_password = attrs.get('current_password')
        new_password = attrs.get('new_password')
        request = self.context.get('request',None)
        user = get_token_user_or_none(request)
        

        
        if not check_password(current_password, user.password):
            raise serializers.ValidationError({"current_password": "Current password is incorrect."})

        if new_password is not None and (len(new_password) < 8 or not any(char.isupper() for char in new_password) or not any(char.islower() for char in new_password) or not any(char.isdigit() for char in new_password) or not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?\'\"\\/~`' for char in new_password)):
            raise serializers.ValidationError({"new_password":('Must Contain 8 Characters, One Uppercase, One Lowercase, One Number and One Special Character')})
        
        return super().validate(attrs)

    def update(self, instance, validated_data):
        new_password = validated_data.get('new_password')
        instance.set_password(new_password)
        
        instance.is_password_already_updated = True
        instance.is_password_reset_required  = False  
        instance.save()
        return instance
    

"""""""""login """


class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField()
    password = serializers.CharField()
    
    class Meta:
        model  = Users
        fields = ['username', 'password']