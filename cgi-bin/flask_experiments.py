import google.oauth2.credentials
import google_auth_oauthlib.flow

import MySQLdb
import private_no_share_dangerous_passwords as pnsdp
SQL_DB = "flask_experiments"

import github_client_secret

import random   # in Python 3, use: import secrets

import json
import urllib
import requests

from googleapiclient.discovery import build

from flask import Flask, request, render_template, url_for, redirect, make_response
app = Flask(__name__)



LOGIN_TIMEOUT   = "00:05:00"
SESSION_TIMEOUT = "00:30:00"



@app.route("/")
def index():
    return render_template("index.html")



@app.route("/login")
def login():
    # connect to the SQL database.  Note that we're using the parameters from
    # the the private config file.
    conn = MySQLdb.connect(host   = pnsdp.SQL_HOST,
                           user   = pnsdp.SQL_USER,
                           passwd = pnsdp.SQL_PASSWD,
                           db     = SQL_DB)

    # Use the google_client_secret.json file to identify the application
    # requesting authorization. The client ID (from that file) and access
    # scopes are required.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "google_client_secret.json",
        scopes=["https://www.googleapis.com/auth/userinfo.email"])

    # Indicate where the API server will redirect the user after the user
    # completes the authorization flow. The redirect URI is required.  Note
    # that the 'external' argument will cause the hostname to be included,
    # which is critical for an redirect that we're going to send to Google!
    flow.redirect_uri = url_for("login_oauth2callback", _external=True)

    nonce = "%032x" % random.getrandbits(128)

    cursor = conn.cursor()
    cursor.execute("""INSERT INTO login_states(nonce,service,expiration) VALUES(%s,"google",ADDTIME(NOW(),%s));""", (nonce,LOGIN_TIMEOUT))
    assert cursor.rowcount == 1
    cursor.close()
    conn.commit()
    conn.close()

    auth_url,state = flow.authorization_url(
        state="google:"+nonce,
        include_granted_scopes="true"
    )

    return redirect(auth_url, code=303)



@app.route("/login_oauth2callback", methods=["GET"])
def login_oauth2callback():
    nonce = request.values["state"]
    code  = request.values["code"]
    scope = request.values["scope"]

    # sanity check that this nonce is for the proper service!
    nonce = nonce.split(":")
    assert len(nonce) == 2   # TODO: make this user error
    assert nonce[0] == "google"   # TODO: also this
    nonce = nonce[1]

    # connect to the SQL database.  Note that we're using the parameters from
    # the the private config file.
    conn = MySQLdb.connect(host   = pnsdp.SQL_HOST,
                           user   = pnsdp.SQL_USER,
                           passwd = pnsdp.SQL_PASSWD,
                           db     = SQL_DB)

    # is the nonce reasonable?  Note that we'll reject anything where the
    # time is too old.
    cursor = conn.cursor()
    cursor.execute("""SELECT * FROM login_states WHERE nonce=%s AND service="google" AND NOW()<expiration;""", (nonce,))
    ok = (cursor.rowcount > 0)
    cursor.close()

    # clean up the nonce from the table (if it happens to exist).  Note that
    # this is common code between the 'ok' and login-expired code
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_states WHERE nonce=%s;", (nonce,))
    rowcount = cursor.rowcount
    cursor.close()

    if not ok:
        conn.commit()
        conn.close()
        if rowcount > 0:
            return "login process has expired"
        else:
            return "invalid nonce"

    # exchange the code for the real token.

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "google_client_secret.json",
        scopes=None,
        state=nonce)

    # I'm not sure why we have to set the redirect_uri here; it seems
    # like it would be redundant.  But the operation will fail if we
    # don't do this.
    flow.redirect_uri = url_for("login_oauth2callback", _external=True)

    flow.fetch_token(code=code)

    cred = flow.credentials
    cred_text = json.dumps({"token"     : cred.token,
                            "token_uri" : cred.token_uri,
                            "scopes"    : cred.scopes})

    # get the user's email address
    userinfo = build("oauth2","v2", credentials=cred).userinfo().get().execute()

    gmail = userinfo["email"]

    # create the session in the database
    cursor = conn.cursor()
    cursor.execute("INSERT INTO sessions(id,gmail,expiration) VALUES(%s,%s, ADDTIME(NOW(),%s));", (nonce,gmail, SESSION_TIMEOUT))
    assert cursor.rowcount == 1
    cursor.close()
    conn.commit()
    conn.close()

    # send the nonce as the cookie ID to the user
    resp = make_response(render_template("loginOK.html", username="russ", gmail=gmail))
    resp.set_cookie("sessionID", nonce)

    return resp



@app.route("/login_github")
def login_github():
    # connect to the SQL database.  Note that we're using the parameters from
    # the the private config file.
    conn = MySQLdb.connect(host   = pnsdp.SQL_HOST,
                           user   = pnsdp.SQL_USER,
                           passwd = pnsdp.SQL_PASSWD,
                           db     = SQL_DB)

    nonce = "%032x" % random.getrandbits(128)

    cursor = conn.cursor()
    cursor.execute("""INSERT INTO login_states(nonce,service,expiration) VALUES(%s,"github",ADDTIME(NOW(),%s));""", (nonce,LOGIN_TIMEOUT))
    assert cursor.rowcount == 1
    cursor.close()
    conn.commit()
    conn.close()

    github_oauth_url = "https://github.com/login/oauth/authorize"
    client_id    = github_client_secret.CLIENT_ID
    redirect_uri = url_for("login_github_oauth2callback", _external=True)
    scope        = ""    # just ask for public info.  All we care about is the GitHub ID of the user that's logging in
    state        = "github:"+nonce

    url = "%s?%s" % (
              github_oauth_url,
              urllib.urlencode({"client_id"    : client_id,
                                "redirect_url" : redirect_uri,
                                "scope"        : scope,
                                "state"        : state,})
          )

    return redirect(url, code=303)



@app.route("/login_github_oauth2callback")
def login_github_oauth2callback():
    nonce = request.values["state"]
    code  = request.values["code"]

    # sanity check that this nonce is for the proper service!
    nonce = nonce.split(":")
    assert len(nonce) == 2   # TODO: make this user error
    assert nonce[0] == "github"   # TODO: also this
    nonce = nonce[1]

    # connect to the SQL database.  Note that we're using the parameters from
    # the the private config file.
    conn = MySQLdb.connect(host   = pnsdp.SQL_HOST,
                           user   = pnsdp.SQL_USER,
                           passwd = pnsdp.SQL_PASSWD,
                           db     = SQL_DB)

    # is the nonce reasonable?  Note that we'll reject anything where the
    # time is too old.
    cursor = conn.cursor()
    cursor.execute("""SELECT * FROM login_states WHERE nonce=%s AND service="github" AND NOW()<expiration;""", (nonce,))
    ok = (cursor.rowcount > 0)
    cursor.close()

    # clean up the nonce from the table (if it happens to exist).  Note that
    # this is common code between the 'ok' and login-expired code
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_states WHERE nonce=%s;", (nonce,))
    rowcount = cursor.rowcount
    cursor.close()

    if not ok:
        conn.commit()
        conn.close()
        if rowcount > 0:
            return "login process has expired"
        else:
            return "invalid nonce"

    # exchange the code for the real token.

    github_token_url = "https://github.com/login/oauth/access_token"
    client_id     = github_client_secret.CLIENT_ID
    client_secret = github_client_secret.CLIENT_SECRET
    # 'code' is taken from the form variables above
    redirect_uri  = url_for("login_github_oauth2callback", _external=True)
    state         = "github:"+nonce

    url = "%s?%s" % (
              github_token_url,
              urllib.urlencode({"client_id"     : client_id,
                                "client_secret" : client_secret,
                                "code"          : code,
                                "redirect_url"  : redirect_uri,
                                "state"         : state,})
          )

    resp = requests.post(url)
    return "%d" % r.status_code)

    return redirect(url, code=303)




    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "google_client_secret.json",
        scopes=None,
        state=nonce)

    # I'm not sure why we have to set the redirect_uri here; it seems
    # like it would be redundant.  But the operation will fail if we
    # don't do this.
    flow.redirect_uri = url_for("login_oauth2callback", _external=True)

    flow.fetch_token(code=code)

    cred = flow.credentials
    cred_text = json.dumps({"token"     : cred.token,
                            "token_uri" : cred.token_uri,
                            "scopes"    : cred.scopes})

    # get the user's email address
    userinfo = build("oauth2","v2", credentials=cred).userinfo().get().execute()

    gmail = userinfo["email"]

    # create the session in the database
    cursor = conn.cursor()
    cursor.execute("INSERT INTO sessions(id,gmail,expiration) VALUES(%s,%s, ADDTIME(NOW(),%s));", (nonce,gmail, SESSION_TIMEOUT))
    assert cursor.rowcount == 1
    cursor.close()
    conn.commit()
    conn.close()

    # send the nonce as the cookie ID to the user
    resp = make_response(render_template("loginOK.html", username="russ", gmail=gmail))
    resp.set_cookie("sessionID", nonce)

    return resp






@app.route("/profile/<string:username>")   # string means no slashes
def profile(username):
    return render_template("profile.html", username=username)



@app.route("/url_check")
def url_check():
    return "The URL to /login is: "+url_for("login")


