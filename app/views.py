from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from app.verify import authentication
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import cache_control
import joblib
import re
import numpy as np
from .process import *
##############################################################################
#                               Main Section                                 #
##############################################################################


def index(request):
    context = {
        'page' : 'home'
    }
    # return HttpResponse("This is Home page")    
    return render(request, "index.html", context)

def log_in(request):
    context = {
        'page' : 'log_in'
    }
    if request.method == "POST":
        # return HttpResponse("This is Home page")  
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username = username, password = password)

        if user is not None:
            login(request, user)
            messages.success(request, "Log In Successful...!")
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid User...!")
            return redirect("log_in")
    # return HttpResponse("This is Home page")    
    return render(request, "log_in.html", context)

def register(request):
    context = {
        'page' : 'register'
    }
    if request.method == "POST":
        fname = request.POST['fname']
        lname = request.POST['lname']
        username = request.POST['username']
        password = request.POST['password']
        password1 = request.POST['password1']
        # print(fname, contact_no, ussername)
        verify = authentication(fname, lname, password, password1)
        if verify == "success":
            user = User.objects.create_user(username, password, password1)          #create_user
            user.first_name = fname
            user.last_name = lname
            user.save()
            messages.success(request, "Your Account has been Created.")
            return redirect("/")
            
        else:
            messages.error(request, verify)
            return redirect("register")
    # return HttpResponse("This is Home page")    
    return render(request, "register.html", context)


@login_required(login_url="log_in")
@cache_control(no_cache = True, must_revalidate = True, no_store = True)
def log_out(request):
    logout(request)
    messages.success(request, "Log out Successfuly...!")
    return redirect("/")


# Function to extract features from a URL
def extract_features(url):
    features = [
        len(url),  # URL length
        url.count('.'),  # Count of '.'
        url.count('-'),  # Count of '-'
        url.count('@'),  # Count of '@'
        url.count('?'),  # Count of '?'
        url.count('='),  # Count of '='
        1 if url.startswith("https") else 0,  # HTTPS presence (1 if exists)
        1 if url.startswith("http") else 0,  # HTTP presence (1 if exists)
        1 if "www." in url else 0,  # WWW presence (1 if exists)
        1 if re.search(r'\d+', url) else 0,  # Numeric presence (1 if any digit exists)
        sum(c.isdigit() for c in url),  # Count of digits
        sum(c.isalpha() for c in url),  # Count of alphabets
        url.count('/'),  # Count of '/'
        url.count('%'),  # Count of '%'
        url.count('&'),  # Count of '&'
        url.count(';'),  # Count of ';'
        url.count('_'),  # Count of '_'
        url.count(':'),  # Count of ':'
        url.count('!'),  # Count of '!'
        url.count('*'),  # Count of '*'
        url.count(','),  # Count of ','
        url.count('$'),  # Count of '$'
        url.count('~')   # Count of '~'
    ]
    return features

safety_thresholds = {
    'URL Length': (5, 75),
    'Dot Count': (3, 7),
    'Dash Count': (0, 2),
    'At Symbol': (0, 0),
    'Question Mark': (0, 2),
    'Equals Sign': (0, 3),
    'HTTPS Presence': (1, 1),  # 1 means safe (https present)
    'HTTP Presence': (0, 0),  # 0 means safe (http not present)
    'WWW Presence': (0, 1),
    'Numeric Presence': (0, 1),
    'Digit Count': (0, 10),
    'Alphabet Count': (10, 100),
    'Slash Count': (1, 5),
    'Percent Count': (0, 2),
    'Ampersand Count': (0, 2),
    'Semicolon Count': (0, 1),
    'Underscore Count': (0, 3),
    'Colon Count': (0, 2),
    'Exclamation Mark': (0, 1),
    'Asterisk': (0, 1),
    'Comma': (0, 2),
    'Dollar Sign': (0, 1),
    'Tilde': (0, 1)
}

# Function to analyze feature safety
def analyze_feature_safety(features):
    safety_analysis = {}
    feature_names = list(safety_thresholds.keys())
    
    for i, feature in enumerate(feature_names):
        min_val, max_val = safety_thresholds[feature]
        status = "Safe" if min_val <= features[i] <= max_val else "Harmful"
        safety_analysis[feature] = {"count": features[i], "status": status}
    
    return safety_analysis

def predict_url(url):
    clf = joblib.load('Dataset/collect_urls/rfc_malicious_url_model.pkl')  # Default model
    label_mapping = {0: 'Benign', 1: 'Defacement', 2: 'Phishing', 3: 'Malware'}
    feature_names = list(safety_thresholds.keys())
    features = extract_features(url)
    predicted_class = clf.predict([features])[0]
    prediction_label = label_mapping[predicted_class]
    feature_safety = analyze_feature_safety(features)
    return prediction_label, feature_safety

@login_required(login_url="log_in")
@cache_control(no_cache = True, must_revalidate = True, no_store = True)
def dashboard(request):
    context = {
        'fname': request.user.first_name, 
        }
    if request.method == "POST":
        url = request.POST['url']
        result, analysis = predict_url(url)
        result = str(result).capitalize()
        print("Result : ",result)
        print("Analysis : ",analysis)
        print('-'*40)
        tech_info = get_technologies(url)
        print("Technology : ",tech_info)
        print('-'*40)
        vulnerability = get_vulnerabilities(tech_info)
        print("Vulnerability : ",vulnerability)
        print('-'*40)
        open_urls = check_open_dirs(url)
        print("Open URLS : ",open_urls)
        context['vulnerability'] = vulnerability
        context['tech_info'] = tech_info
        context['open_urls'] = open_urls
        context['result'] = result
        context['analysis'] = analysis
        context['url'] = url
    return render(request, "dashboard.html",context)
