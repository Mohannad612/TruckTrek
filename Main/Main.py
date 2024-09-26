from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os
from functools import wraps

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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link to the user
    user = db.relationship('User', backref='profile', lazy=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    year = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    faculty = db.Column(db.String(50), nullable=False)
    tags = db.Column(db.String(100), nullable=False)
    image1 = db.Column(db.String(200), nullable=True)
    image2 = db.Column(db.String(200), nullable=True)
    image3 = db.Column(db.String(200), nullable=True)
    image4 = db.Column(db.String(200), nullable=True)
    image5 = db.Column(db.String(200), nullable=True)

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

# Custom decorator to check if the user has a profile
def profile_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        profile = UserProfile.query.filter_by(id=current_user.id).first()
        if profile is None:  # If the user has no profile, redirect them to the profile setup page
            flash('Please set up your profile first.')
            return redirect(url_for('profile'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/home')
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
    # Fetch the current user's profile
    profile = UserProfile.query.filter_by(user_id=current_user.id).first()

    # If no profile exists, create a new one
    if profile is None:
        profile = UserProfile(
            user_id=current_user.id,  # Link the profile to the user
            name='',  
            age=0,
            year='',
            description='',
            faculty='',
            tags=''
        )
        db.session.add(profile)
        db.session.commit()  # Commit the new profile to the database
        flash('New profile created.')
        return redirect(url_for('profile'))  # Prevent further execution after profile creation

    # Handle Save Profile (for updating profile details)
    if request.method == 'POST' and 'save_profile' in request.form:
        name = request.form.get('name', '').strip()
        try:
            age = int(request.form.get('age', 0))
        except ValueError:
            flash('Age must be an integer.')
            return redirect(url_for('profile'))

        if not (18 <= age <= 100):
            flash('Age must be between 18 and 100.')
            return redirect(url_for('profile'))

        year = request.form.get('year', '').strip()
        description = request.form.get('description', '').strip()
        faculty = request.form.get('faculty', '').strip()
        tags = request.form.get('tags', '').strip()

        # Update profile details
        profile.name = name
        profile.age = age
        profile.year = year
        profile.description = description
        profile.faculty = faculty
        profile.tags = tags

        db.session.commit()
        flash('Profile updated successfully.')
        return redirect(url_for('profile'))

    # Handle Save Photos (for uploading profile images)
    if request.method == 'POST' and 'save_photos' in request.form:
        photos = request.files.getlist('photos')
        remove_images = request.form.getlist('remove_images')

        # Handle image removal
        for img in remove_images:
            current_image = getattr(profile, img)
            if current_image:
                setattr(profile, img, None)
                user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{profile.user_id}")
                image_path = os.path.join(user_folder, current_image)
                if os.path.exists(image_path):
                    os.remove(image_path)

        # Handle photo uploads
        if photos:
            available_slots = sum([1 for i in range(1, 6) if not getattr(profile, f'image{i}')])

            if len(photos) > available_slots:
                flash('Not enough image slots available. Please remove existing images.')
            else:
                for photo in photos:
                    if allowed_file(photo.filename):
                        for i in range(1, 6):
                            current_image = getattr(profile, f'image{i}')
                            if not current_image:  # Save to the first empty slot
                                filename = secure_filename(f"user_{profile.user_id}_photo_{i}.{photo.filename.rsplit('.', 1)[1].lower()}")
                                user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{profile.user_id}")
                                os.makedirs(user_folder, exist_ok=True)
                                photo_path = os.path.join(user_folder, filename)
                                photo.save(photo_path)
                                setattr(profile, f'image{i}', filename)  # Set image field
                                break  # Exit after saving to first empty slot
                flash('Profile photo updated successfully.')
        else:
            flash('No photos were uploaded.')

        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('profile.html', profile=profile)

@app.route('/profiles', methods=['GET', 'POST'])
@login_required
@profile_required  # Ensure the user has a profile before accessing
def profiles():
    viewed_profiles = UserLike.query.filter_by(liker_id=current_user.id).all()
    viewed_profile_ids = [like.liked_profile_id for like in viewed_profiles]
    next_profile = UserProfile.query.filter(UserProfile.id.notin_(viewed_profile_ids)).first()

    if not next_profile:
        return render_template('no_more_profiles.html')

    if request.method == 'POST':
        profile_id = request.form['profile_id']
        action = request.form['action']

        if action == 'like':
            new_like = UserLike(liker_id=current_user.id, liked_profile_id=profile_id)
            db.session.add(new_like)
            db.session.commit()
            flash('You liked the profile.')
        elif action == 'pass':
            new_pass = UserLike(liker_id=current_user.id, liked_profile_id=profile_id)
            db.session.add(new_pass)
            db.session.commit()
            flash('You passed over this profile.')

        return redirect(url_for('profiles'))

    return render_template('profiles.html', profile=next_profile)

@app.route('/likes', methods=['GET', 'POST'])
@login_required
@profile_required  # Ensure the user has a profile before accessing
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

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
