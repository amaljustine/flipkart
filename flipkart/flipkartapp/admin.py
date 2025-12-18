from django.contrib import admin

# Register your models here.
from django.contrib.auth.admin import UserAdmin
from .models import Users

@admin.register(Users)
class UsersAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'created_date',
        'modified_date',
        'email',
        'username',
        'date_joined',
        'is_verified',
        'is_admin',
        'is_staff',
        'is_superuser',
        'is_active',
        
    )
    list_filter = (
        'created_date',
        'modified_date',
        'date_joined',
        'last_login',
        'is_verified',
        'is_admin',
        'is_staff',
        'is_superuser',
        'is_active',
    )
    exclude = ['password']