from __future__ import unicode_literals
from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import User, Book, Review
import datetime
import bcrypt
import re
from django.db.models import Count
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')

def index(request):
    return render(request, 'bookapp/index.html')

def exists(request):
    data = {'email': request.POST['email'], 'password': request.POST['password']}
    results = User.objects.login(data)
    if len(results) > 0:
        for error in results:
            messages.add_message(request, messages.ERROR, error)
        return redirect('/')
    else:
        request.session['email'] = request.POST['email']
        request.session['first_name'] = User.objects.get(email=data['email']).first_name
        request.session['user_id'] = User.objects.get(email=data['email']).id
        return redirect('/home')

def create(request):
    data = {'first_name': request.POST['first_name'], 'last_name': request.POST['last_name'], 'email': request.POST['email'], 'password': request.POST['password'], 'passwordcon': request.POST['passwordcon']}
    results = User.objects.register(data)
    if len(results) > 0:
        for error in results:
            messages.add_message(request, messages.ERROR, error)
        return redirect('/')
    else:
        pw = bcrypt.hashpw(data['password'].encode('utf8'), bcrypt.gensalt())
        User.objects.create(first_name=data['first_name'],last_name=data['last_name'], email=data['email'], password=pw)
        request.session['first_name'] = User.objects.get(email=data['email']).first_name
        request.session['user_id'] = User.objects.get(email=data['email']).id
        return redirect('/home')
