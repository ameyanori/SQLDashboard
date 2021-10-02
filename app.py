from flask import Flask, request, session, redirect, url_for, render_template, flash
import psycopg2
import json
import ast
import pandas as pd
import string
from flask_login import LoginManager
import psycopg2.extras
import re
import string
import random
import smtplib  
import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = app.config['SECRET_KEY']
pg_con = psycopg2.connect(dbname=app.config['DB_NAME'], user=app.config['DB_USER'], password=app.config['DB_PASS'])



def sendemail(recipient, subject, code):
  SENDER = 'administrator@ameyanori.link'  
  SENDERNAME = 'System @ ameyanori.link'
  RECIPIENT  = recipient
  USERNAME_SMTP = app.config['SMTP_USER']
  PASSWORD_SMTP = app.config['SMTP_PASS']
  HOST = "email-smtp.us-west-2.amazonaws.com"
  PORT = 587
  SUBJECT = subject
  BODY_HTML = f"""<html>
  <head>
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
  </head>
  <td style="padding:45px" align="left" colspan="2">
			<h1 style="color:#222222;font-weight:bold;font-size:24px;margin:10px 0 16px 0"><span class="il">Verify</span> your email</h1>
			<p style="margin-bottom:16px;font-size:16px">
				Thank you for registering on ameyanori.link!<br>In order to verify this email to your account, <span class="il">verify</span> you must complete this verification step.<br><br>Your <span class="il">verification</span> <span class="il">link</span> is: </p><p>https://jjdpc.ameyanori.link/verify?token={code}</p><br>
			<p></p>
      <p style="margin-bottom:16px;font-size:16px">
        Alternatively, you can click on this button:
      </p>
      <p></p>
<a href="https://jjdpc.ameyanori.link/verify?token={code}" style="font-weight:bold;padding:12px 24px;background:#fba342;color:white;border-radius:4px" target="_blank" data-saferedirecturl="https://www.google.com/url?q=https://jjdpc.ameyanori.link/verify?token={code}"><span class="il">VERIFY</span> EMAIL</a>  
			<hr style="background-color:#fbc241;height:2px;border:0;margin:24px 0">

  </html>
              """
              
  msg = MIMEMultipart('alternative')
  msg['Subject'] = SUBJECT
  msg['From'] = email.utils.formataddr((SENDERNAME, SENDER))
  msg['To'] = RECIPIENT
  part2 = MIMEText(BODY_HTML, 'html')
  msg.attach(part2)
  server = smtplib.SMTP(HOST, PORT)
  server.ehlo()
  server.starttls()
  server.ehlo()
  server.login(USERNAME_SMTP, PASSWORD_SMTP)
  server.sendmail(SENDER, RECIPIENT, msg.as_string())
  server.close()

@app.route('/verify')
def verify():
    token = request.args.get('token')
    cursor = pg_con.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("update users set email_code = 'Verified' where email_code = %s", (token,))
    cursor.close()
    pg_con.commit()
    return redirect(url_for('login'))

@app.route('/')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))

@app.route('/login/', methods=['GET', 'POST'])
def login():

    cursor = pg_con.cursor(cursor_factory=psycopg2.extras.DictCursor)
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        print(password)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        # Fetch one record and return result
        account = cursor.fetchone()
        if account:
            password_rs = account['password']
            print(password_rs)
            # If account exists in users table in out database
            if check_password_hash(password_rs, password):
                # Create session data, we can access this data in other routes
                cursor.execute('SELECT whitelist FROM users WHERE username = %s', (username,))
                whitelist = cursor.fetchone()
                if account['email_code'] != 'Verified':
                    flash('Account not verified, please check your email to verify your account.')
                else:
                    if whitelist == [False]:
                        flash('Account not whitelisted, please contact ameya@ameyanori.link if you feel you need access.')
                    else:
                        session['loggedin'] = True
                        session['id'] = account['id']
                        session['type'] = account['type']
                        session['username'] = account['username']
                        # Redirect to home page
                        return redirect(url_for('home'))
            else:
                # Account doesnt exist or username/password incorrect
                flash('Incorrect username/password')
        else:
            # Account doesnt exist or username/password incorrect
            flash('Incorrect username/password')
    return render_template('login.html')



@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if session['loggedin'] == True and session['type'] == 'admin':
        cursor = pg_con.cursor(cursor_factory=psycopg2.extras.DictCursor)
        if request.method == 'POST' and 'name' in request.form:
            print(request.form)
            id = request.form['id']
            fullname = request.form['name']
            username = request.form['username']
            whitelist = request.form['whitelist']
            type = request.form['type']
            cursor.execute('UPDATE users SET fullname = %s, username = %s, whitelist = %s, type = %s WHERE id = %s', (fullname, username, whitelist, type, id,))
            pg_con.commit()
        cursor.execute('SELECT id, fullname, username, email, whitelist, type FROM USERS')
        data = cursor.fetchall()
        return render_template('admin.html', data = data, headings=("ID", "Full Name", "Username", "Email", "Whitelisted", "Type"))

    else:
        return render_template('404.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = pg_con.cursor(cursor_factory=psycopg2.extras.DictCursor)
    def get_random_string(length):
        # Random string with the combination of lower and upper case
        letters = string.ascii_uppercase
        result_str = ''.join(random.choice(letters) for i in range(length))
        return result_str 
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        _hashed_password = generate_password_hash(password)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        print(account)
        # If account exists show error and validation checks
        if account:
            flash('Account already exists!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        elif not username or not password or not email:
            flash('Please fill out the form!')
        else:
            # Account doesnt exists and the form data is valid, now insert new account into users table
            cursor.execute("INSERT INTO users (fullname, username, password, email, whitelist, type) VALUES (%s,%s,%s,%s,%s,%s)", (fullname, username, _hashed_password, email, False, 'user'))
            pg_con.commit()
            flash('You have successfully registered! For security purposes, you need to verify the email you provided, please check your email, and click the link attached.')
            code = get_random_string(60)
            sendemail(email, "Verification at ameyanori.link", code)
            cursor.execute("UPDATE USERS SET email_code = %s WHERE email = %s", (code, email))
            pg_con.commit()
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        flash('Please fill out the form!')
    # Show registration form with message (if any)
    return render_template('register.html')

@app.route("/add", methods=["GET", "POST"])
def add():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
         name=request.form["name"]
         num=request.form["num"]
         sro=request.form['sro']
         cur = pg_con.cursor()
         cur.execute("INSERT INTO entries (entry_name, entry_num, entry_sro) VALUES (%s, %s, %s)", (name, num, sro))
         pg_con.commit()
         cur.close()
         return redirect(url_for('table'))
    return render_template('add.html')


@app.route("/remove", methods=["GET", "POST"])
def remove():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        num = int(request.form["outid"])
        cur = pg_con.cursor()
        print(num)
        cur.execute("DELETE FROM entries WHERE entry_num = %s", (num,))
        pg_con.commit()
        cur.close()
        return redirect(url_for('table'))
    return render_template('remove.html')

@app.route("/table",methods=["GET","POST"])
def table():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    cur = pg_con.cursor()
    cur.execute("""SELECT * from entries""")
    data = cur.fetchall()
    pg_con.commit()
    cur.close()
    return render_template('table.html', data=data, headings=("Number", "Name", "Checker"))

@app.route('/profile')
def profile(): 
    cursor = pg_con.cursor(cursor_factory=psycopg2.extras.DictCursor)
    # Check if user is loggedin
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM users WHERE id = %s', [session['id']])
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(host="0.0.0.0", port="8000")

