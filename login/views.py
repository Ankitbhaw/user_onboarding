from django.http import HttpRequest, HttpResponse
from django.shortcuts import render, redirect
from .models import *
import requests
from django.core.mail import send_mail
from allauth.socialaccount.models import SocialAccount


# jenkins credentials
jenkins_url = "https://jenkins-dev.primathontech.co.in"
username = "ankit"
api_token = "11191e4d1027ee36717be594174f1902fb"
auth = (username, api_token)

# sonar Credentials
Sonar_login = "AnkitBhawsar"
Sonar_password = "Primathon@123"

# login to Admin Account for Sonar


def loginAsAdmin():

    api_endpoint = f"https://sonarqube.primathontech.co.in/api/authentication/login?login={Sonar_login}&password={Sonar_password}"
    response = requests.post(api_endpoint)
    if response:
        xcsrf_token = response.cookies.get("XSRF-TOKEN")
        jwt_session = response.cookies.get("JWT-SESSION")
        if not LoginSonar.objects.filter(login=Sonar_login):
            LoginSonar.objects.create(
                login=Sonar_login, XSRF_TOKEN=xcsrf_token, JWT_SESSION=jwt_session
            )
        else:
            LoginSonar.objects.filter(login=Sonar_login).update(
                XSRF_TOKEN=xcsrf_token, JWT_SESSION=jwt_session
            )
        return True
    else:
        return False


def home(request):
    if not loginAsAdmin():
        return redirect("/")
    return render(request, "home.html")


# Check if email address has @Primathon.in


def has_primathon_in(email):
    return "primathon.in" in email.split("@")[-1]


# Google Authentication


def google_auth(request):
    social_info = SocialAccount.objects.filter(user=request.user)
    if social_info:

        if not has_primathon_in(social_info[0].extra_data["email"]):
            return redirect("/")

        login = social_info[0]
        email = social_info[0].extra_data["email"]
        name = social_info[0].extra_data["name"]
        password = f"{social_info[0]}@123"

        # if User.objects.filter(login=login):
        # return redirect("/")
        response = render(request, "createUser.html")

        if check_user_exists_sonar(email) == False:
            createSonarUser(login, name, password, email)
        if check_user_exists_jenkins(email) == False:
            createJenkinsUser(name, login, password, email)
        # User.objects.create(login=login, email=email)
        return response


# Check if user Exists or not in Sonar


def check_user_exists_sonar(email):
    accessToken = LoginSonar.objects.get(login=Sonar_login)
    if accessToken:
        XSRF_TOKEN = accessToken.XSRF_TOKEN
        JWT_SESSION = accessToken.JWT_SESSION

    headers = {
        "Cookie": f"XSRF-TOKEN={XSRF_TOKEN};JWT-SESSION={JWT_SESSION}",
        "Content-Type": "application/json",
        "Connection": "keep-alive",
        "Referer": "https://sonarqube.primathontech.co.in/projects",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "X-XSRF-TOKEN": f"{XSRF_TOKEN}",
    }
    api_endpoint = f"https://sonarqube.primathontech.co.in/api/users/search?q={email}"
    response = requests.post(api_endpoint, headers=headers)
    if response.status_code == 200:
        users = response.json().get("users", [])
        for user in users:
            if user["email"] == email:
                return True
            else:
                return False
    else:

        print(f"Unexpected response: {response.status_code}")
        return None


# Create Sonar User


def createSonarUser(login, name, password, email):
    accessToken = LoginSonar.objects.get(login=Sonar_login)
    if accessToken:
        XSRF_TOKEN = accessToken.XSRF_TOKEN
        JWT_SESSION = accessToken.JWT_SESSION

    print(XSRF_TOKEN, JWT_SESSION)
    headers = {
        "Cookie": f"XSRF-TOKEN={XSRF_TOKEN};JWT-SESSION={JWT_SESSION}",
        "Content-Type": "application/json",
        "Connection": "keep-alive",
        "Referer": "https://sonarqube.primathontech.co.in/projects",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "X-XSRF-TOKEN": f"{XSRF_TOKEN}",
    }
    api_endpoint = f"https://sonarqube.primathontech.co.in/api/users/create?login={login}&email={email}&local=true&name={name}&password={password}"
    response = requests.post(api_endpoint, headers=headers)
    if response.status_code == 200:
        sendingEmail(
            login,
            name,
            email,
            password,
            "sonarqube",
            "https://sonarqube.primathontech.co.in/sessions/new?return_to=%2F",
        )


# Check if user Exists or not in jenkins


def check_user_exists_jenkins(email):
    api_endpoint = (
        f"https://jenkins-dev.primathontech.co.in/asynchPeople/api/json?depth=2"
    )

    response = requests.get(api_endpoint, auth=auth)

    if response.status_code == 200:
        users = response.json().get("users", [])
        for user in users:

            if user.get("user", {}).get("property", {})[-1].get("address", "") == email:
                return True
        return False
    else:

        print(f"Unexpected response: {response.status_code}")
        return None


# Create jenkins user


def createJenkinsUser(name, new_username, password, email):
    create_user_url = f"{jenkins_url}/securityRealm/createAccountByAdmin"

    user_data = {
        "username": new_username,
        "password1": password,
        "password2": password,
        "fullname": name,
        "email": email,
    }

    response = requests.post(create_user_url, auth=auth, data=user_data)

    if response.status_code == 200:
        print(f"User '{new_username}' created successfully.")
        addJenkinsGlobalRole(new_username)
        sendingEmail(
            new_username,
            name,
            email,
            password,
            "jenkins",
            "https://jenkins-dev.primathontech.co.in/login?from=%2F",
        )

    else:
        print("Failed to create user. Error:", response.text)


# Assign Builder Role By Default in Jenkins


def addJenkinsGlobalRole(new_username):

    url = f"{jenkins_url}/role-strategy/strategy/assignRole"
    data = {"type": "globalRoles", "roleName": "builder", "sid": new_username}
    response = requests.post(
        url,
        auth=auth,
        data=data,
    )
    if response.status_code == 200:
        print(f"Assigned global role 'builder' to user '{new_username}' successfully.")

    else:
        print(
            f"Failed to assign global role 'builder' to user '{new_username}'. Status code: {response.status_code}"
        )


# Sending Email


def sendingEmail(login, name, email, password, type, url):
    message = f"""your account on {type} is created successfully.
            your Credentials are :
            login : {login} 
            name : {name} 
            email : {email} 
            password : {password} 

        You can login using these credentials here 
        {url} """

    send_mail(
        f"{type} User created",
        message,
        "ankitbhawsar1018@gmail.com",
        [f"{email}"],
        fail_silently=False,
    )
