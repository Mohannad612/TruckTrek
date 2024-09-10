from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os

# Initialize the Flask application
app = Flask(__name__)

# Set up the application configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = 'SecureHome'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size: 16MB

# Initialize the database and bcrypt
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# Profile model
class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    year = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    faculty = db.Column(db.String(50), nullable=False)
    tags = db.Column(db.String(100), nullable=False)
    image1 = db.Column(db.String(200), nullable=True)

# Likes model
class UserLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    liker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    liked_profile_id = db.Column(db.Integer, db.ForeignKey('user_profile.id'), nullable=False)

    liker = db.relationship('User', foreign_keys=[liker_id])
    liked_profile = db.relationship('UserProfile', foreign_keys=[liked_profile_id])

# Forms
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('That username already exists.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# Utility function for allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('home.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home')) 
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = request.form['name']
        try:
            age = int(request.form['age'])
        except ValueError:
            flash('Age must be an integer.')
            return redirect(url_for('profile'))

        if age < 18 or age > 100:
            flash('Age must be between 18 and 100')
            return redirect(url_for('profile'))

        year = request.form['year']
        description = request.form['description']
        faculty = request.form['faculty']
        tags = request.form['tags']
        photos = request.files.getlist('photos')

        if len(photos) > 5:
            flash('You can upload a maximum of 5 photos.')
            photos = photos[:5]

        profile = UserProfile(
            name=name, age=age, year=year, description=description,
            faculty=faculty, tags=tags
        )
        db.session.add(profile)
        db.session.commit()

        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{profile.id}")
        os.makedirs(user_folder, exist_ok=True)

        if photos and allowed_file(photos[0].filename):
            filename = secure_filename(f"user_{profile.id}_photo_1.{photos[0].filename.rsplit('.', 1)[1].lower()}")
            photo_path = os.path.join(user_folder, filename)
            photos[0].save(photo_path)
            profile.image1 = photo_path

        db.session.commit()
        flash('Profile created successfully.')
        return redirect(url_for('home'))

    return render_template('profile.html')

@app.route('/profiles', methods=['GET', 'POST'])
@login_required
def profiles():
    profiles = UserProfile.query.all()
    if request.method == 'POST':
        profile_id = request.form['profile_id']
        action = request.form['action']
        if action == 'like':
            new_like = UserLike(liker_id=current_user.id, liked_profile_id=profile_id)
            db.session.add(new_like)
            db.session.commit()
            flash('You liked the profile.')
        elif action == 'pass':
            flash('You passed the profile.')
        return redirect(url_for('profiles'))
    return render_template('profiles.html', profiles=profiles)

@app.route('/likes', methods=['GET', 'POST'])
@login_required
def likes():
    sent_likes = UserLike.query.filter_by(liker_id=current_user.id).all()
    received_likes = UserLike.query.filter_by(liked_profile_id=current_user.id).all()

    view = request.args.get('view', 'sent')  # Default view is 'sent', can be switched to 'received'
    
    if view == 'received':
        return render_template('likes.html', sent_likes=sent_likes, received_likes=received_likes, view='received')
    else:
        return render_template('likes.html', sent_likes=sent_likes, received_likes=received_likes, view='sent')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Run the application
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
