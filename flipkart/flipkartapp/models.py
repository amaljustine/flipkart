from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager,PermissionsMixin
from django_acl.models import AbstractDateFieldMix
from django.utils.translation import gettext_lazy as _
from django_acl.utils.helper import acl_has_perms


class UserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError(_('The username must be set'))

        user = self.model(username=username, **extra_fields)
        if password:
            user.set_password(password.strip())
            
        user.save()


        
        return user

    def create_superuser(self, username, password, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_verified', True)
        extra_fields.setdefault('is_admin', True)
     
        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff = True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser = True.'))
        
        return self.create_user(username, password, **extra_fields)


class Users(AbstractBaseUser,PermissionsMixin, AbstractDateFieldMix):
    
    phone                         = models.CharField(max_length=15, blank=True, null=True)
    is_verified                   = models.BooleanField(default=False)
    username                      = models.CharField(_('username'), max_length = 300, unique = True, blank = True, null = True)
    is_admin                      = models.BooleanField(default = False)
    is_staff                      = models.BooleanField(default = False)
    is_active                     = models.BooleanField(_('Is Active'), default=True)
    email                         = models.EmailField(_('email'), unique = True, max_length = 255, blank = True, null = True)
    first_name                    = models.CharField(_('First Name'),max_length=225,null=True,blank=True)
    last_name                     = models.CharField(_('last_name'),max_length=225,null=True,blank=True) 
    date_joined                   = models.DateTimeField(_('date_joined'),  auto_now_add = True, blank = True, null = True)
    last_login                    = models.DateTimeField(_('last_login'), blank = True, null = True)
    is_logged_in                  = models.BooleanField(default = False)



    USERNAME_FIELD = 'username'
    objects = UserManager()

    def __str__(self):
        return self.username
    

    def has_perm(self, perm, obj = None):
        "Does the user have a specific permission?"
        return self.is_admin

 
    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        return True
    
    
    
    def has_acl_perms(self, perm, obj = None):
        return acl_has_perms(self, perm, obj=obj)
    
            
            
    def _password_has_been_changed(self):
        return self.original_password != self.password



"""""generated access token"""

class GeneratedAccessToken(AbstractDateFieldMix):
    token = models.TextField()
    user = models.ForeignKey(Users, on_delete=models.CASCADE, null=True, blank=True)
    
    def __str__(self):
        return self.token