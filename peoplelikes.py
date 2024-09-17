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

# Initialize the database, bcrypt, and login manager
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Define the UserProfile model
class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    age = db.Column(db.Integer)
    year = db.Column(db.String(50))
    description = db.Column(db.Text)
    faculty = db.Column(db.String(100))
    tags = db.Column(db.String(200))
    image1 = db.Column(db.String(200))
    image2 = db.Column(db.String(200))

    user = db.relationship('User', backref='profile')

# Define the Likes model
class UserLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    liker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    liked_profile_id = db.Column(db.Integer, db.ForeignKey('user_profile.id'), nullable=False)

    liker = db.relationship('User', foreign_keys=[liker_id])
    liked_profile = db.relationship('UserProfile', foreign_keys=[liked_profile_id])

# Utility function for allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def home():
    return render_template('home.html', user=current_user)

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

# Run the application
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
