from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    flash,
    abort,
)
from sqlalchemy import desc
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
    UserMixin,
)
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
from dotenv import load_dotenv
from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url
import cloudinary
from dotenv import load_dotenv

load_dotenv()  # загружаем переменные из .env файла
database_url = os.getenv(
    "postgresql://postgres.zgihjicinzgjhmsnetsv:Karelo.pinamar24@aws-0-us-west-1.pooler.supabase.com:6543/postgres"
)

# Настройка Cloudinary
cloudinary.config(
    cloud_name="dsbxe2uhk",
    api_key="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpnaWhqaWNpbnpnamhtc25ldHN2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjU0MDI5NTcsImV4cCI6MjA0MDk3ODk1N30.JqGxXoqHRX1tPpWM67eeaHx9Q8E34vVizrpNhkR5ktg",
    api_secret="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpnaWhqaWNpbnpnamhtc25ldHN2Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTcyNTQwMjk1NywiZXhwIjoyMDQwOTc4OTU3fQ.9psVSqPTm6g44HV4YbZjc_kegeAomjcWO3kPtPwNFCI",
)


def upload_file_to_cloudinary(file):
    try:
        upload_result = upload(file)
        return upload_result["secure_url"]
    except Exception as e:
        print(f"An error occurred during file upload: {e}")
        return None


app = Flask(__name__)
app.secret_key = "7yrtu76209846yyyrqqll"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///specialists.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "7yrtu76209846yyyrqqll"  # Замените на случайную строку

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class Specialist(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(100), nullable=False)
    specialty = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer)
    about = db.Column(db.Text)
    education = db.Column(db.Text)
    certifications = db.Column(db.Text)
    profile_picture = db.Column(db.String(200))
    reviews_received = db.relationship(
        "Review",
        foreign_keys="Review.specialist_id",
        backref="reviewed_specialist",
        lazy="dynamic",
    )
    reviews_written = db.relationship(
        "Review", foreign_keys="Review.author_id", backref="author", lazy="dynamic"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def average_rating(self):
        reviews = self.reviews_received
        if reviews.count() > 0:
            return sum(review.rating for review in reviews) / reviews.count()
        return None

    @property
    def is_authenticated(self):
        return True


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    specialist_id = db.Column(
        db.Integer, db.ForeignKey("specialist.id"), nullable=False
    )
    author_id = db.Column(db.Integer, db.ForeignKey("specialist.id"), nullable=False)
    # specialist = db.relationship("Specialist", foreign_keys=[specialist_id], backref=db.backref("reviews_received", lazy=True))
    # author = db.relationship("Specialist", foreign_keys=[author_id], backref=db.backref("reviews_written", lazy=True))

    def __repr__(self):
        return f"<Review {self.id} for Specialist {self.specialist_id}>"


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


def create_app():
    @app.route("/edit_review/<int:review_id>", methods=["GET", "POST"])
    @login_required
    def edit_review(review_id):
        review = Review.query.get_or_404(review_id)
        if review.author != current_user:
            abort(403)
        if request.method == "POST":
            review.content = request.form["content"]
            review.rating = int(request.form["rating"])
            db.session.commit()
            flash("Your review has been updated!", "success")
            return redirect(url_for("view_profile", id=review.specialist_id))
        return render_template("edit_review.html", review=review)

    @app.route("/delete_review/<int:review_id>", methods=["POST"])
    @login_required
    def delete_review(review_id):
        review = Review.query.get_or_404(review_id)
        if review.author != current_user:
            abort(403)
        db.session.delete(review)
        db.session.commit()
        flash("Your review has been deleted!", "success")
        return redirect(url_for("view_profile", id=review.specialist_id))

    @app.route("/profile/<int:id>")
    def view_profile(id):
        specialist = Specialist.query.get_or_404(id)
        page = request.args.get("page", 1, type=int)
        sort = request.args.get("sort", "recent")
        if sort == "highest":
            reviews = specialist.reviews_received.order_by(
                Review.rating.desc()
            ).paginate(page=page, per_page=5)
        elif sort == "lowest":
            reviews = specialist.reviews_received.order_by(Review.rating).paginate(
                page=page, per_page=5
            )
        else:
            reviews = specialist.reviews_received.order_by(
                Review.created_at.desc()
            ).paginate(page=page, per_page=5)
        return render_template(
            "profile.html", specialist=specialist, reviews=reviews, sort=sort
        )

    @app.route("/edit_profile/<int:id>", methods=["GET", "POST"])
    @login_required
    def edit_profile(id):
        specialist = Specialist.query.get_or_404(id)
        if current_user.id != specialist.id:
            flash("You do not have permission to edit this profile.", "danger")
            return redirect(url_for("home"))

        if request.method == "POST":
            specialist.name = request.form["name"]
            specialist.specialty = request.form["specialty"]
            specialist.location = request.form["location"]
            specialist.experience = request.form.get("experience", type=int)
            specialist.about = request.form["about"]
            specialist.education = request.form["education"]
            specialist.certifications = request.form["certifications"]

            if "profile_picture" in request.files:
                file = request.files["profile_picture"]
            if file and file.filename != "":
                print(f"Attempting to upload file: {file.filename}")
            try:
                file_url = upload_file_to_cloudinary(file)
                print(f"Cloudinary upload result: {file_url}")
                if file_url:
                    specialist.profile_picture = file_url
                    print(f"Profile picture URL set to: {specialist.profile_picture}")
            except Exception as e:
                print(f"Error during file upload: {e}")
                flash(f"Error uploading file: {str(e)}", "error")

            db.session.commit()
            print(f"After commit - Profile picture URL: {specialist.profile_picture}")
            flash("Your profile has been updated!", "success")
            return redirect(url_for("view_profile", id=specialist.id))

        return render_template("edit_profile.html", specialist=specialist)

    @app.route("/add_review/<int:specialist_id>", methods=["GET", "POST"])
    @login_required
    def add_review(specialist_id):
        specialist = Specialist.query.get_or_404(specialist_id)
        if request.method == "POST":
            content = request.form["content"]
            rating = int(request.form["rating"])
            if 1 <= rating <= 5:
                review = Review(
                    content=content,
                    rating=rating,
                    specialist_id=specialist.id,
                    author_id=current_user.id,
                )
                db.session.add(review)
                db.session.commit()
                flash("Your review has been added!", "success")
                return redirect(url_for("view_profile", id=specialist.id))
            else:
                flash("Rating must be between 1 and 5", "danger")
        return render_template("add_review.html", specialist=specialist)

    @app.route("/register", methods=["GET", "POST"])
    def register_specialist():
        if current_user.is_authenticated:
            return redirect(url_for("home"))
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            name = request.form.get("name")
            specialty = request.form.get("specialty")
            location = request.form.get("location")

            if Specialist.query.filter_by(username=username).first():
                flash(
                    "Username already exists. Please choose a different one.", "danger"
                )
                return redirect(url_for("register_specialist"))

            specialist = Specialist(
                username=username, name=name, specialty=specialty, location=location
            )
            specialist.set_password(password)
            db.session.add(specialist)
            db.session.commit()

            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("home"))

        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            specialist = Specialist.query.filter_by(username=username).first()

            if specialist and specialist.check_password(password):
                login_user(specialist)
                flash("Logged in successfully.", "success")
                next_page = request.args.get("next")
                return redirect(next_page or url_for("home"))
            else:
                flash("Invalid username or password", "danger")

        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("You have been logged out successfully.", "info")
        return redirect(url_for("home"))

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
            "search.html",
            specialists=specialists,
            specialty=specialty,
            location=location,
        )

    @app.route("/")
    def home():
        return render_template("home.html")

    return app


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)
