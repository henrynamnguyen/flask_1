from flask import Blueprint, render_template, request, flash, redirect, url_for
from . import db
from .models import User
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,login_required, logout_user, current_user #UserMixin in models.py is for this current_user

auth = Blueprint('auth',__name__)

@auth.route('/login', methods=['POST','GET']) #GET request is by default, POST request is not
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:    
            if check_password_hash(user.password, password):
                flash('Logged in successfully', category='success')
                login_user(user,remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Wrong password!', category='error')
        else:
            flash('Account does not exist', category='error')
       
        
    return render_template("login.html", user = current_user ) #text = "Testing", user = "Henry", boolean = False) #we can pass any variables we want into render_template and use them in html file.

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['POST','GET'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()

        if len(email) < 4:
            flash('Email must be at least 4 characters', category='error')
        elif len(firstName) < 2:
            flash('First name must be at least 2 characters', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters', category='error')
        elif user.email:
            flash('Account already existed', category='error')
        else:
            #create a user
            new_user = User(email=email, firstName= firstName, password= generate_password_hash(password1, method='sha256'))
            #add user to the database
            db.session.add(new_user)
            db.session.commit()
            flash('Account created!', category='success')
            login_user(new_user,remember=True)

            #redirect to the homepage
            return redirect(url_for('views.home'))
     
    return render_template("sign-up.html", user = current_user)