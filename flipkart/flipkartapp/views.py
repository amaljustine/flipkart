from django.utils import timezone
import os
import sys
from typing import Any
from django.shortcuts import render

from flipkartapp.schemas import LoginResponseSchema, UserInfoSchema
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken, TokenError
from flipkart.helpers.helper import get_object_or_none
from rest_framework.permissions import IsAuthenticated
from flipkart.helpers.response import ResponseInfo
from flipkartapp.models import GeneratedAccessToken, Users
from flipkartapp.serializers import ChangePasswordSerializer, CreateOrUpdateUserSerializer, LoginSerializer
from rest_framework.permissions import BasePermission


from rest_framework import generics,status, filters
from drf_yasg.utils import swagger_auto_schema
from rest_framework.response import Response
from flipkart.helpers.custom_messages import (
    _success, 
    _record_not_found,  
    _user_not_found,
)
from django.contrib import auth
from drf_yasg import openapi


# Create your views here.

# class IsSelf(BasePermission):
#     def has_permission(self, request, view):
#         user_id = request.GET.get('id')
#         return not user_id or int(user_id) == request.user.id

class IsSelfOrAdmin(BasePermission):
    def has_permission(self, request, view):
        user_id = request.GET.get('id')

        # Admin / staff can access anyone
        if request.user.is_superuser:
            return True

        # Normal users: only their own data
        if user_id and int(user_id) == request.user.id:
            return True

        # If no id is passed, allow self
        return user_id is None


class CreateOrUpdateUserApiView(generics.GenericAPIView):
    def __init__(self, **kwargs):
        self.response_format = ResponseInfo().response
        super(CreateOrUpdateUserApiView, self).__init__(**kwargs)
        
    serializer_class = CreateOrUpdateUserSerializer

    @swagger_auto_schema(tags=["Users"])
    def post(self, request):
        try:

            serializer = self.serializer_class(data=request.data, context = {'request' : request})
            if not serializer.is_valid():
                self.response_format['status_code'] = status.HTTP_400_BAD_REQUEST
                self.response_format["status"] = False
                self.response_format["errors"] = serializer.errors
                return Response(self.response_format, status=status.HTTP_400_BAD_REQUEST)

            user_instance = get_object_or_none(Users,pk=serializer.validated_data.get('user', None))

            serializer = self.serializer_class(user_instance, data=request.data, context = {'request' : request})
            if not serializer.is_valid():
                self.response_format['status_code'] = status.HTTP_400_BAD_REQUEST
                self.response_format["status"] = False
                self.response_format["errors"] = serializer.errors
                return Response(self.response_format, status=status.HTTP_400_BAD_REQUEST)
            
            serializer.save()
            
            self.response_format['status_code'] = status.HTTP_201_CREATED
            self.response_format["message"] = _success
            self.response_format["status"] = True
            return Response(self.response_format, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.response_format['status_code'] = status.HTTP_500_INTERNAL_SERVER_ERROR
            self.response_format['status'] = False
            self.response_format['message'] = f'exc_type : {exc_type},fname : {fname},tb_lineno : {exc_tb.tb_lineno},error : {str(e)}'
            return Response(self.response_format, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 
        




"""""""""change password"""


class UpdateUsprepasswordApiView(generics.GenericAPIView):
    def __init__(self, **kwargs):
        self.response_format = ResponseInfo().response
        super(UpdateUsprepasswordApiView, self).__init__(**kwargs)
        
    serializer_class = ChangePasswordSerializer
    permission_classes = (IsAuthenticated,)
    
    @swagger_auto_schema(tags=["Users"])
    def post(self, request):
        try:

            serializer = self.serializer_class(data=request.data, context = {'request' : request})

            if not serializer.is_valid():
                self.response_format['status_code'] = status.HTTP_400_BAD_REQUEST
                self.response_format["status"] = False
                self.response_format["errors"] = serializer.errors
                return Response(self.response_format, status=status.HTTP_400_BAD_REQUEST)

            user_instance = get_object_or_none(Users,pk=serializer.validated_data.get('user', None))

            serializer = self.serializer_class(user_instance, data=request.data, context = {'request' : request})
            if not serializer.is_valid():
                self.response_format['status_code'] = status.HTTP_400_BAD_REQUEST
                self.response_format["status"] = False
                self.response_format["errors"] = serializer.errors
                return Response(self.response_format, status=status.HTTP_400_BAD_REQUEST)
                
            
            serializer.save()
            
            self.response_format['status_code'] = status.HTTP_201_CREATED
            self.response_format["message"] = _success
            self.response_format["status"] = True
            return Response(self.response_format, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.response_format['status_code'] = status.HTTP_500_INTERNAL_SERVER_ERROR
            self.response_format['status'] = False
            self.response_format['message'] = f'exc_type : {exc_type},fname : {fname},tb_lineno : {exc_tb.tb_lineno},error : {str(e)}'
            return Response(self.response_format, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 
    




"""""""""login"""""""""

class LoginApiView(generics.GenericAPIView):
    
    def __init__(self, **kwargs: Any):
        self.response_format = ResponseInfo().response
        super(LoginApiView, self).__init__(**kwargs)
        
    serializer_class = LoginSerializer

    @swagger_auto_schema(tags=["Authorization"])
    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            
            if not serializer.is_valid():
                # Return errors if the serializer is invalid
                self.response_format['status'] = False
                self.response_format['errors'] = serializer.errors
                return Response(self.response_format, status=status.HTTP_400_BAD_REQUEST)
            
            user = auth.authenticate(
                username=serializer.validated_data.get("username", ""),
                password=serializer.validated_data.get("password", ""),
            )
            if user:
                if not user.is_active:
                    self.response_format['status_code'] = status.HTTP_403_FORBIDDEN
                    self.response_format['status'] = False
                    self.response_format['message'] = "Your account is inactive. Please contact support."
                    return Response(self.response_format, status=status.HTTP_403_FORBIDDEN)

                else:
                    user.is_logged_in = True
                    user.last_login = timezone.now()
                    user.save(update_fields=['is_logged_in', 'last_login'])

                    serializer = LoginResponseSchema(user, context={"request": request})
                    refresh = RefreshToken.for_user(user)
                    token = str(refresh.access_token)

                    # user.refresh_token = refresh
                    # user.save(update_fields=['refresh_token'])
                    

                    data = {
                            'user': serializer.data,
                            'token': token,
                            'refresh': str(refresh),
                        }
                    
                    GeneratedAccessToken.objects.create(user=user, token=token)
                        
                    self.response_format['status_code'] = status.HTTP_200_OK
                    self.response_format['status'] = True
                    self.response_format['data'] = data
                    return Response(self.response_format, status=status.HTTP_200_OK)
            else:
                
                # Invalid credentials case
                self.response_format['status_code'] = status.HTTP_400_BAD_REQUEST
                self.response_format["message"] = "Invalid credentials. Please try again."
                self.response_format["status"] = False
                return Response(self.response_format, status=status.HTTP_400_BAD_REQUEST)


        except Exception as es:
            # Handle any server-side errors
            self.response_format['status_code'] = status.HTTP_500_INTERNAL_SERVER_ERROR
            self.response_format['status'] = False
            self.response_format['message'] = str(es)
            return Response(self.response_format, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



"""""user details view"""


class RetrieveUserInfoApiView(generics.GenericAPIView):
    def __init__(self, **kwargs):
        self.response_format = ResponseInfo().response
        super(RetrieveUserInfoApiView, self).__init__(**kwargs)
        
    serializer_class = UserInfoSchema
    permission_classes = (IsAuthenticated,IsSelfOrAdmin)
    # authentication_classes    = [BlacklistedJWTAuthentication]

    id = openapi.Parameter('id', openapi.IN_QUERY, type=openapi.TYPE_STRING, required=True, description="Enter id")
    
    @swagger_auto_schema(tags=["Users"],manual_parameters=[id])
    def get(self, request):
        
        try:
            
            instance = get_object_or_none(Users, pk=request.GET.get('id', None))
            print("instannnnn",instance)
            print("QUERY PARAMS:", request.GET)
            print("ID FROM QUERY:", request.GET.get('id'))
            print("AUTH USER ID:", request.user.id)

            if instance is None:
                self.response_format['status_code'] = status.HTTP_204_NO_CONTENT
                self.response_format["message"] = _record_not_found
                self.response_format["status"] = False
                return Response(self.response_format, status=status.HTTP_200_OK)
                
            data = self.serializer_class(instance, context={'request': request}).data 
            
            self.response_format['status_code'] = status.HTTP_200_OK
            self.response_format["data"] = data 
            self.response_format["message"] = _success
            self.response_format["status"] = True
            return Response(self.response_format, status=status.HTTP_200_OK)

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.response_format['status_code'] = status.HTTP_500_INTERNAL_SERVER_ERROR
            self.response_format['status'] = False
            self.response_format['message'] = f'exc_type : {exc_type},fname : {fname},tb_lineno : {exc_tb.tb_lineno},error : {str(e)}'
            return Response(self.response_format, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 
        