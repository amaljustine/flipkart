






from flipkartapp.models import Users
from rest_framework import serializers


"""login response schema"""

class LoginResponseSchema(serializers.ModelSerializer):


    class Meta:
        model = Users

        fields=["id","email","username",]


"""""user info schema"""


class UserInfoSchema(serializers.ModelSerializer):


    class Meta:
        model = Users

        fields=["id","username","email",]