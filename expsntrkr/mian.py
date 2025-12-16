from flask import Flask, redirect, render_template, url_for, request
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from wtforms import StringField, PasswordField, SubmitField, SelectField
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required,current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "secretkey"

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_name = db.Column(db.String(250))

class transactionForm(FlaskForm):
    transactionName = StringField("transaction_name")
    submit = SubmitField("Add")
    transactionType = SelectField('transaction type', choices=[], validators=[DataRequired()])

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
    form = transactionForm()
    if request.method == "POST":
        if form.validate_on_submit():
            selectedValue = request.form.get("transactionName")

            entry = Transaction(transactionType=selectedValue)
            db.session.add(entry)
            db.session.commit()
        transaction_name = request.form.get('transaction_name')

    new_transaction = Transaction(transaction_name=transaction_name)
    db.session.add(new_transaction)
    db.session.commit()

    return render_template("Addtransaction.html")


if __name__ == '__main__':
    app.run(debug=True)