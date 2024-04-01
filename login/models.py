from django.db import models


# Create your models here.
class User(models.Model):
    login = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)


class LoginSonar(models.Model):
    login = models.CharField(max_length=100)
    XSRF_TOKEN = models.CharField(max_length=100)
    JWT_SESSION = models.CharField(max_length=200)
