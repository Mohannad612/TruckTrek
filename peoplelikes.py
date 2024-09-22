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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Custom decorator to check if the user has a profile
def profile_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        profile = UserProfile.query.filter_by(id=current_user.id).first()
        if profile is None:
            flash('Please set up your profile first.')
            return redirect(url_for('profile'))
        return f(*args, **kwargs)
    return decorated_function

# Home routes
@app.route('/')
@login_required
def home():
    return render_template('home.html', user=current_user)

# Abdul Kalam Part(needed for code processing)
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    profile = UserProfile.query.filter_by(id=current_user.id).first()

    # If the user has no profile yet, display a reminder
    if profile is None:
        flash('Please create your profile to proceed.')

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

        # Check if profile exists
        if profile:
            existing_photos = [profile.image1, profile.image2, profile.image3, profile.image4, profile.image5]
            
            # Update profile details
            profile.name = name
            profile.age = age
            profile.year = year
            profile.description = description
            profile.faculty = faculty
            profile.tags = tags

            # Handle photo uploads
            if len(photos) > 0:  # Only check for photo upload requirement if photos are included
                if len(photos) < 3 and len([photo for photo in existing_photos if photo]) < 3:
                    flash('You must have at least 3 photos.')
                    return redirect(url_for('profile'))

                if len(photos) > 5:
                    flash('You can upload a maximum of 5 photos.')
                    return redirect(url_for('profile'))

                # Save the uploaded images
                user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{profile.id}")
                os.makedirs(user_folder, exist_ok=True)

                for i in range(min(len(photos), 5)):
                    if allowed_file(photos[i].filename):
                        filename = secure_filename(f"user_{profile.id}_photo_{i+1}.{photos[i].filename.rsplit('.', 1)[1].lower()}")
                        photo_path = os.path.join(user_folder, filename)
                        photos[i].save(photo_path)
                        setattr(profile, f'image{i+1}', filename)  # Update image fields dynamically

                # Retain old images if new ones are not uploaded
                for i in range(1, 6):
                    if not getattr(profile, f'image{i}') and len(existing_photos) >= i and existing_photos[i - 1]:
                        setattr(profile, f'image{i}', existing_photos[i - 1])
            else:
                # If no new photos are uploaded, retain existing ones
                for i in range(1, 6):
                    if not getattr(profile, f'image{i}') and len(existing_photos) >= i and existing_photos[i - 1]:
                        setattr(profile, f'image{i}', existing_photos[i - 1])

        else:
            # Create new profile if it does not exist
            profile = UserProfile(
                id=current_user.id, name=name, age=age, year=year,
                description=description, faculty=faculty, tags=tags
            )
            db.session.add(profile)

            # Handle photo uploads for new profile
            if len(photos) < 3:
                flash('You must upload at least 3 photos.')
                return redirect(url_for('profile'))

            if len(photos) > 5:
                flash('You can upload a maximum of 5 photos.')
                return redirect(url_for('profile'))

            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{profile.id}")
            os.makedirs(user_folder, exist_ok=True)

            for i in range(min(len(photos), 5)):
                if allowed_file(photos[i].filename):
                    filename = secure_filename(f"user_{profile.id}_photo_{i+1}.{photos[i].filename.rsplit('.', 1)[1].lower()}")
                    photo_path = os.path.join(user_folder, filename)
                    photos[i].save(photo_path)
                    setattr(profile, f'image{i+1}', filename)  # Set image fields dynamically

        db.session.commit()
        flash('Profile updated successfully.')
        return redirect(url_for('profile'))

    return render_template('profile.html', profile=profile)

# Profiles routes
@app.route('/profiles', methods=['GET', 'POST'])
@login_required
@profile_required
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

# Likes routes
@app.route('/likes', methods=['GET', 'POST'])
@login_required
@profile_required 
def likes():
    sent_likes = UserLike.query.filter_by(liker_id=current_user.id).all()
    received_likes = UserLike.query.filter_by(liked_profile_id=current_user.id).all()

    matches = []
    for sent in sent_likes:
        if UserLike.query.filter_by(liker_id=sent.liked_profile_id, liked_profile_id=current_user.id).first():
            matches.append(sent.liked_profile)

    view = request.args.get('view', 'sent')

    return render_template('likes.html', 
                           sent_likes=sent_likes, 
                           received_likes=received_likes, 
                           matches=matches, 
                           view=view)

if __name__ == '__main__':
    app.run(debug=True)
