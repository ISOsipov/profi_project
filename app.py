from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    current_user,
    UserMixin,
)
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

# login_manager = LoginManager()
# login_manager.init_app(app)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///specialists.db"
app.config["SECRET_KEY"] = "your-secret-key"  # Замените на случайную строку

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()


class Specialist(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(100), nullable=False)
    specialty = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer)
    about = db.Column(db.Text)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


def create_app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///specialists.db"
    app.config["SECRET_KEY"] = "your-secret-key"

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return Specialist.query.get(int(user_id))

    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.args.get("token")
            if not token:
                return jsonify({"message": "Token is missing!"}), 401
            try:
                data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            except:
                return jsonify({"message": "Token is invalid!"}), 401
            return f(*args, **kwargs)

        return decorated

    @app.route("/profile/<int:id>")
    def view_profile(id):
        specialist = Specialist.query.get_or_404(id)
        return render_template("profile.html", specialist=specialist)

    @app.route("/edit_profile/<int:id>", methods=["GET", "POST"])
    @login_required
    def edit_profile(id):
        specialist = Specialist.query.get_or_404(id)
        if current_user.id != specialist.id:
            return "Доступ запрещен", 403

        if request.method == "POST":
            specialist.name = request.form["name"]
            specialist.specialty = request.form["specialty"]
            specialist.location = request.form["location"]
            specialist.experience = request.form.get("experience", type=int)
            specialist.about = request.form["about"]
            db.session.commit()
            return redirect(url_for("view_profile", id=specialist.id))

        return render_template("edit_profile.html", specialist=specialist)

    @app.route("/register", methods=["GET", "POST"])
    def register_specialist():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            name = request.form.get("name")
            specialty = request.form.get("specialty")
            location = request.form.get("location")

            if Specialist.query.filter_by(username=username).first():
                return "Пользователь с таким именем уже существует", 400

            specialist = Specialist(
                username=username, name=name, specialty=specialty, location=location
            )
            specialist.set_password(password)
            db.session.add(specialist)
            db.session.commit()

            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            specialist = Specialist.query.filter_by(username=username).first()
            if specialist and specialist.check_password(password):
                # Генерация токена
                token = jwt.encode(
                    {
                        "username": specialist.username,
                        "exp": datetime.datetime.utcnow()
                        + datetime.timedelta(hours=24),
                    },
                    app.config["SECRET_KEY"],
                )

                # В реальном приложении здесь вы бы сохранили токен в сессии или отправили клиенту
                # Для простоты мы просто перенаправим на страницу поиска
                return redirect(url_for("search_specialists", token=token))
            else:
                return render_template(
                    "login.html", error="Неверное имя пользователя или пароль"
                )

        return render_template("login.html")

    @app.route("/search", methods=["GET"])
    # @token_required
    def search_specialists():
        specialty = request.args.get("specialty")
        location = request.args.get("location")

        query = Specialist.query
        if specialty:
            query = query.filter(Specialist.specialty.ilike(f"%{specialty}%"))
        if location:
            query = query.filter(Specialist.location.ilike(f"%{location}%"))

        specialists = query.all()
        # return jsonify([ {"name": s.name, "specialty": s.specialty, "location": s.location} for s in specialists])
        if request.headers.get("Accept") == "application/json":
            return jsonify(
                [
                    {"name": s.name, "specialty": s.specialty, "location": s.location}
                    for s in specialists
                ]
            )

        # Если это не API-запрос, отображаем HTML-страницу
        return render_template(
            "search.html", specialists=specialists, searched=(specialty or location)
        )

    @app.route("/")
    def home():
        return "Welcome to the Specialist Finder App!"

    return app


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)
