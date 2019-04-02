import google.oauth2.credentials
import google_auth_oauthlib.flow

import MySQLdb
import private_no_share_dangerous_passwords as pnsdp
SQL_DB = "flask_experiments"

import random   # in Python 3, use: import secrets

from flask import Flask, request, render_template, url_for, redirect
app = Flask(__name__)



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

    # Use the client_secret.json file to identify the application requesting
    # authorization. The client ID (from that file) and access scopes are required.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['https://www.googleapis.com/auth/userinfo.email'])

    # Indicate where the API server will redirect the user after the user
    # completes the authorization flow. The redirect URI is required.  Note
    # that the 'external' argument will cause the hostname to be included,
    # which is critical for an redirect that we're going to send to Google!
    flow.redirect_uri = url_for("login_oauth2callback", _external=True)

    nonce = "%032x" % random.getrandbits(128)

    cursor = conn.cursor()
    cursor.execute("""INSERT INTO login_states(nonce,expiration) VALUES(%s,ADDTIME(NOW(),"00:00:30"));""", (nonce,))
    assert cursor.rowcount == 1
    cursor.close()
    conn.commit()
    conn.close()

    auth_url,state = flow.authorization_url(
        state=nonce,
        include_granted_scopes='true'
    )

    return redirect(auth_url, code=303)



@app.route("/login_oauth2callback", methods=['GET'])
def login_oauth2callback():
    v = request.values
    return "\n".join(["%s->%s" % (k,v[k]) for k in v])



@app.route("/profile/<string:username>")   # string means no slashes
def profile(username):
    return render_template("profile.html", username=username)



@app.route("/url_check")
def url_check():
    return "The URL to /login is: "+url_for('login')


