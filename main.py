from flask import (
    Flask,
    render_template,
    request,
    url_for,
    redirect,
    flash,
    send_from_directory,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    current_user,
    logout_user,
)

app = Flask(__name__)

app.config["SECRET_KEY"] = "1984GeorgeOrwell"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# db.create_all()


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if User.query.filter_by(email=request.form.get("email")).first():
            flash("Email already exists, log in!")
            return redirect(url_for("login"))

        password = request.form.get("password")

        hash_and_salted_password = generate_password_hash(
            password, method="pbkdf2:sha256", salt_length=8
        )
        email = request.form.get("email")
        name = request.form.get("name")
        new_user = User(
            email=email,
            name=name,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        print(f'\n\033[92m[registered]\033[0m username:"{name}"\temail: "{email}"\tpassword: "{"*" * len(password)}"\n')
        login_user(new_user)
        return redirect(url_for("dashboard"))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Incorrect email, please try again.")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):
            flash("Incorrect password, please try again.")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("dashboard"))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", name=current_user.name, logged_in=True)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route('/news')
def news():
    return render_template("news.html", logged_in=current_user.is_authenticated)

@app.route('/contact')
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)

if __name__ == "__main__":
    app.run(debug=True)
