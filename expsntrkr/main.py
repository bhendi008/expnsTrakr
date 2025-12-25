from flask import Flask, redirect, render_template, url_for, request
from flask_wtf import FlaskForm
from flask_googlecharts import GoogleCharts
from flask_googlecharts import BarChart
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerRangeField
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import DeclarativeMeta, declarative_base
from sqlalchemy.orm import sessionmaker
import requests
import json
import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required,current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt


app = Flask(__name__)
bcrypt = Bcrypt(app)
charts = GoogleCharts(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///transactions"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "secretkey"

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class AlchemyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj.__class__, DeclarativeMeta):
            fields = {}
            for field in [x for x in dir(obj) if not x.startswith('_') and x != 'metadata']:
                data = obj.__getattribute__(field)
                try:
                    json.dumps(data)
                    fields[field] = data
                except TypeError:
                    fields[field] = None
            return fields
        return json.JSONEncoder.default(self, obj)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(250), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.datetime.now)
    amount = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(100), nullable=False)

class transactionForm(FlaskForm):
    submit = SubmitField("Submit")

class registerForm(FlaskForm):
    username = StringField(validators=(InputRequired(), Length(min=4,max=20)), render_kw={"placeholder":"username"}),
    password = PasswordField(validators=(InputRequired(), Length(min=4,max=20)), render_kw={"placeholder":"password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).all()

        if existing_user_username:
            raise ValidationError("username already taken!!")
        
    def validate_password(self, password):
        existing_user_password = User.query.filter_by(password=password.data).all()

        if existing_user_password:
            raise ValidationError("a user already exists!!")
        
class loginForm():
    username = StringField(validators=(InputRequired(), Length(min=4, max=20)), render_kw={"placeholder": "username"})
    password = PasswordField(validators=(InputRequired(), Length(min=4, max=20)), render_kw={"placeholder": "password"})
    submit = SubmitField("login")

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def Home():
    return render_template("Home.html")

@app.route('/Register', methods=["GET","POST"])
def Register():
    form = registerForm()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            return render_template("Register.html", error="Username already taken!")

        hashed_password = bcrypt.generate_password_hash(password)

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("Login"))
    return render_template('Register.html', form=form)

@app.route('/Login', methods=["GET","POST"])
def Login():
    form = loginForm()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return render_template("Dashboard.html")
        else:
            return render_template("Login.html", error="invalid username or password", form=form)
        
    return render_template("Login.html")
    
@app.route("/Dashboard")
@login_required
def Dashboard():
    return render_template("Dashboard.html", username=current_user.username)

@app.route("/Addtransaction", methods=["GET", "POST"])
def Addtransaction():
    if request.method == 'POST':
        transaction_content = request.form['content']
        transaction_amount = request.form['amount']
        transaction_type = request.form['type']
        new_transaction = Transaction(content=transaction_content, amount=transaction_amount, type=transaction_type)
        try:
            db.session.add(new_transaction)
            db.session.commit()
            return redirect('/Addtransaction')
        except:
            return "error mofo"
    else:
        transactions = Transaction.query.order_by().all()
        transaction_json = json.dumps(transactions, cls=AlchemyEncoder)
        with open("data.json", "a") as f:
            json.dump([transaction_json], f, indent=2)
            print(transaction_json)
                
        return render_template('Addtransaction.html', transactions=transactions)
    return render_template("Addtransaction.html")

@app.route('/delete/<int:id>')
def delete(id):
    transactionToDelete = Transaction.query.get_or_404(id)

    try:
        db.session.delete(transactionToDelete)
        db.session.commit()
        return redirect('/Addtransaction')
    
    except:
        return "error while deleting?? tsk tsk tsk:-("

@app.route("/transactionSummary", methods=["POST", "GET"])
def transactionSummary():
    return render_template('transactionSummary.html', charts=charts)

@app.route("/transactionHistory", methods=["POST", "GET"])
def transactionHistory():
    transactions = Transaction.query.order_by().all()
    return render_template('transactionHistory.html', transactions=transactions)

if __name__ == '__main__':
    app.run(debug=True)