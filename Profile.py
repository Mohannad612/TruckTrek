#imports
from flask import Flask, render_template, request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename

#application setup
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size: 16MB

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

#for utility functions

def allowed_file(filename):
    return '.' in filename and            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#saving the profile

def save_profile(age, year, description, faculty, tags, photos):
    user_id = len(os.listdir(app.config['UPLOAD_FOLDER'])) + 1
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{user_id}')
    os.makedirs(user_folder, exist_ok=True)

    profile_data = {
        'age': age,
        'year': year,
        'description': description,
        'faculty': faculty,
        'tags': tags
    }

    with open(os.path.join(user_folder, 'profile.txt'), 'w') as f:
        for key, value in profile_data.items():
            f.write(f"{key}: {value}\n")

    photo_paths = []
    for i, photo in enumerate(photos):
        if photo and allowed_file(photo.filename):
            filename = secure_filename(f"user_{user_id}_photo_{i + 1}.{photo.filename.rsplit('.', 1)[1].lower()}")
            photo_path = os.path.join(user_folder, filename)
            photo.save(photo_path)
            photo_paths.append(photo_path)

    flash('Profile saved successfully!')
    return redirect(url_for('index'))

#the main route for home page

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        age = int(request.form['age'])
        if age < 18 or age > 100:
            flash('Age must be between 18 and 100')
            return redirect(url_for('index'))

        year = request.form['year']
        description = request.form['description']
        faculty = request.form['faculty']
        tags = request.form['tags']
        photos = request.files.getlist('photos')
        return save_profile(age, year, description, faculty, tags, photos)
    return render_template('profile.html')
#running the app
if __name__ == '__main__':
    app.run(debug=True)
