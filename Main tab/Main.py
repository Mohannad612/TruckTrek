# Imports
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os

# Application setup
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size: 16MB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///profiles.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Database model for user profiles
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

# Database model for user likes
class UserLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('user_profile.id'), nullable=False)

# Utility function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Saving the profile
def save_profile_to_db(name, age, year, description, faculty, tags, photos):
    profile = UserProfile(
        name=name,
        age=age,
        year=year,
        description=description,
        faculty=faculty,
        tags=tags
    )
    
    db.session.add(profile)
    db.session.commit()  # Commit to generate profile.id

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{profile.id}")
    os.makedirs(user_folder, exist_ok=True)

    photo_paths = []
    for i, photo in enumerate(photos):
        if photo and allowed_file(photo.filename):
            file_ext = photo.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f"user_{profile.id}_photo_{i + 1}.{file_ext}")
            photo_path = os.path.join(user_folder, filename)
            try:
                photo.save(photo_path)
                photo_paths.append(photo_path)
            except Exception as e:
                flash(f'Failed to save photo {i + 1}: {e}')
                continue  # Skip this photo and continue with others

    if len(photo_paths) > 0:
        profile.image1 = photo_paths[0]
    if len(photo_paths) > 1:
        profile.image2 = photo_paths[1]
    if len(photo_paths) > 2:
        profile.image3 = photo_paths[2]
    if len(photo_paths) > 3:
        profile.image4 = photo_paths[3]
    if len(photo_paths) > 4:
        profile.image5 = photo_paths[4]
    
    db.session.commit()  # Commit the updated profile with image paths

    flash('Profile saved successfully!')
    return redirect(url_for('index'))

# The main route for the home page
@app.route('/')
def index():
    return render_template('home.html')

# Route for the profile creation page
@app.route('/profile', methods=['GET', 'POST'])
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

        return save_profile_to_db(name, age, year, description, faculty, tags, photos)

    return render_template('profile.html')

# Route for the profiles listing page
@app.route('/profiles', methods=['GET', 'POST'])
def profiles():
    all_profiles = UserProfile.query.all()

    if request.method == 'POST':
        profile_id = request.form.get('profile_id')
        action = request.form.get('action')
        
        if action == 'like':
            save_like_to_db(profile_id)
        flash(f'You {action}d profile {profile_id}')
        return redirect(url_for('profiles'))

    return render_template('profiles.html', profiles=all_profiles)

# Route for the likes page
@app.route('/likes')
def likes():
    user_id = 1  # Replace with dynamic user ID if applicable
    liked_profiles = UserLike.query.filter_by(profile_id=user_id).all()
    received_likes = UserLike.query.join(UserProfile).filter(UserProfile.id == UserLike.profile_id).all()
    
    return render_template('likes.html', liked_profiles=liked_profiles, received_likes=received_likes)

# Utility function to save likes to the database
def save_like_to_db(profile_id):
    new_like = UserLike(profile_id=profile_id)
    db.session.add(new_like)
    db.session.commit()

# Running the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure the database tables are created
    app.run(debug=True)
