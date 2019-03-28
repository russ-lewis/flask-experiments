from flask import Flask, request, render_template, url_for, redirect

app = Flask(__name__)



print("foobar")



@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login():
    

    return redirect(url_for("profile", username="russ"), code=303)

@app.route("/profile/<string:username>")   # string means no slashes
def profile(username):
    return render_template("profile.html", username=username)

@app.route("/url_check")
def url_check():
    return "The URL to /login is: "+url_for('login')


