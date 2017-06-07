from __future__ import unicode_literals
from django.db import models
from django.db.models import Count
import re, bcrypt
#import Count
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')

class UserManager(models.Manager):
    def login(self, data):
        errors = []
        try:
            user = User.objects.get(email=data['email'])
        except:
            errors.append('User not found, please register or check login credentials.')
            return errors
        print(user.password)
        if bcrypt.hashpw(data['password'].encode('utf8'), user.password.encode('utf8')) == user.password.encode('utf8'):
             pass
        else:
             errors.append('Your password does not match')

        return errors

    def register(self, data):
        errors = []
        if data['first_name'] == "":
            errors.append("First name cannot be blank")
        elif len(data['first_name']) < 2:
            errors.append("Name cannot be shorter than 2 characters.")
        if data['last_name'] == "":
            errors.append("Last name cannot be blank")
        elif len(data['last_name']) < 2:
            errors.append("Last name cannot be shorter than 2 characters.")
        if data['email'] == "":
            errors.append("Email cannot be blank")
        elif not EMAIL_REGEX.match(data['email']):
            errors.append("Invalid email address")
        try:
            User.objects.get(email=data['email'])
            errors.append("There is already an existing account with that email address")
        except:
            pass
        if data['password'] == "":
            errors.append("Password cannot be blank")
        elif len(data['password']) < 8:
            errors.append("Password cannot be shorter than 8 characters")
        if data['passwordcon'] != data['password']:
            errors.append('Passwords do not match')
        return errors

class User(models.Model):
    first_name = models.CharField(max_length=75)
    last_name = models.CharField(max_length=75)
    email = models.CharField(max_length=75)
    password = models.CharField(max_length=75)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

class Club(models.Model):
    book_id = models.IntegerField()
    owner_id = models.ForeignKey(User, related_name="owner")
    users = models.ManyToManyField(User, related_name="members")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # objects = ClubManager()

class Review(models.Model):
    rating = models.CharField(max_length=10)
    content = models.TextField()
    book_id = models.IntegerField()
    user_id = models.ForeignKey(User, related_name="reviewer")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # objects = ReviewManager()

class Bookshelf(models.Model):
    user_id = models.ForeignKey(User, related_name="user_books")
    book_id = models.IntegerField()
    favorite = models.BooleanField()
    status = models.CharField(max_length=200)
