from flask import Flask, render_template, url_for, redirect, flash, request, jsonify
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from sqlalchemy.orm import aliased
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from datetime import timezone
import json
import uuid
import secrets

socket_tokens = {}

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'SecureHome'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'crazylogic749@gmail.com'
app.config['MAIL_PASSWORD'] = 'lnws rcaa esrf djrv'

mail = Mail(app)
socketio = SocketIO(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    profile_pic = db.Column(db.String(500), nullable=False, default='https://images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com/f/d733c1e1-d7d1-4f92-9abb-628b1aa5af6a/dfzlns7-c3089e5b-f230-4a67-b56a-706f105c6bed.jpg?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1cm46YXBwOjdlMGQxODg5ODIyNjQzNzNhNWYwZDQxNWVhMGQyNmUwIiwiaXNzIjoidXJuOmFwcDo3ZTBkMTg4OTgyMjY0MzczYTVmMGQ0MTVlYTBkMjZlMCIsIm9iaiI6W1t7InBhdGgiOiJcL2ZcL2Q3MzNjMWUxLWQ3ZDEtNGY5Mi05YWJiLTYyOGIxYWE1YWY2YVwvZGZ6bG5zNy1jMzA4OWU1Yi1mMjMwLTRhNjctYjU2YS03MDZmMTA1YzZiZWQuanBnIn1dXSwiYXVkIjpbInVybjpzZXJ2aWNlOmZpbGUuZG93bmxvYWQiXX0.GER60TdONmCscZ3QvsDf0bVQRk9bsnhdB7FB9RviXK0')
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    age = db.Column(db.Integer, nullable=True)
    year = db.Column(db.String(120), nullable=True)
    description = db.Column(db.String(500), nullable=True)
    faculty = db.Column(db.String(120), nullable=True)
    username = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    interests = db.Column(db.String(500), nullable=True)
    posts = db.relationship('Post', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True, foreign_keys='Like.user_id')
    unique_id = db.Column(db.String(36), unique=True, default=str(uuid.uuid4()))

    def get_token(self, expires_sec=300):
        serial = Serializer(app.config['SECRET_KEY'])
        return serial.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_token(token):
        serial = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = serial.loads(token, max_age=300)['user_id']
        except:
            return None
        return User.query.get(user_id)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(500), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    profile_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    read = db.Column(db.Boolean, default=False)
    read_timestamp = db.Column(db.DateTime, nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class AuthForm(FlaskForm):
    first_name = StringField(validators=[Length(min=2, max=120)], render_kw={"placeholder": "First Name"})
    last_name = StringField(validators=[Length(min=2, max=120)], render_kw={"placeholder": "Last Name"})
    username = StringField(validators=[InputRequired(), Email(), Length(min=4, max=120)], render_kw={"placeholder": "Email", "type": "email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Submit')
    mode = HiddenField('mode', default='login')

    def validate_on_submit(self):
        if self.mode.data == 'register':
            self.first_name.validators = [InputRequired(), Length(min=2, max=120)]
            self.last_name.validators = [InputRequired(), Length(min=2, max=120)]
        else:
            self.first_name.validators = [Length(min=0, max=120)]
            self.last_name.validators = [Length(min=0, max=120)]
        
        print(super(AuthForm, self).validate())
        return super(AuthForm, self).validate()

    def validate_username(self, username):
        if self.mode.data == 'register':
            existing_user_username = User.query.filter_by(username=username.data).first()
            if existing_user_username:
                raise ValidationError('That username already exists. Please choose a different one.')


class ResetRequestForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Email(), Length(min=4, max=120)], render_kw={"placeholder": "Email", "type": "email"})
    submit = SubmitField('Submit')

class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField('Submit')

@app.route('/')
def start():
    return render_template('start.html')

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    form = AuthForm()
    if form.validate_on_submit():
        if form.mode.data == 'login':
            user = User.query.filter_by(username=form.username.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
        elif form.mode.data == 'register':
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data, password=hashed_password, unique_id=str(uuid.uuid4()), first_name=form.first_name.data, last_name=form.last_name.data)
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('auth'))
    else:
        if form.mode.data == 'register' and not form.first_name.data and not form.last_name.data:
            flash('Please enter your first and last name.', 'danger')
    return render_template('auth.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    all_users = User.query.filter(User.id != current_user.id).all()
    users = {}
    for user in all_users:
        users[user.id] = {
            'username': user.username,
            'profile_pic': user.profile_pic,
            'name': user.first_name + ' ' + user.last_name,
            'interests': user.interests,
            'description': user.description,
            'year': user.year,
            'faculty': user.faculty,
            'id': user.id
        }
    return render_template('dashboard.html', users=users)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth'))

def send_mail(user):
    token = user.get_token()
    msg = Message('Password Reset Request', recipients=[user.username], sender='noreply@project.com')
    msg.body = f'''To reset your password, please follow the link below:
    
    {url_for('reset_token', token=token, _external=True)}
    
    If you didn't request a password reset, please ignore this message.
    '''
    mail.send(msg)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    form = ResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            send_mail(user)
            flash('Reset request sent. Check your email.', 'success')
            return redirect(url_for('auth'))
        else:
            flash('No account found with that email.', 'danger')
    return render_template('reset_request.html', title='Reset Request', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_token(token)
    if user is None:
        flash('That is an invalid or expired token. Please try again.', 'warning')
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash('Passwords must match.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated! You are now able to log in.', 'success')
            return redirect(url_for('auth'))

    return render_template('change_password.html', title="Change Password", form=form)

@app.route('/chat')
@login_required
def chat():
    all_users = User.query.filter(User.id != current_user.id).all()
    users = {}

    # Alias the Like table to differentiate between the columns
    like_alias_1 = aliased(Like)
    like_alias_2 = aliased(Like)

    mutual_likes = db.session.query(like_alias_1.profile_id).join(
        like_alias_2, (like_alias_1.user_id == current_user.id) & (like_alias_1.profile_id == like_alias_2.user_id)
    ).filter(
        like_alias_2.profile_id == current_user.id
    ).all()

    mutual_user_ids = {like.profile_id for like in mutual_likes}

    for user in all_users:
        if user.id not in mutual_user_ids:
            continue

        latest_message = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.recipient_id == user.id)) |
            ((Message.sender_id == user.id) & (Message.recipient_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()

        if latest_message:
            timestamp_utc = latest_message.timestamp.replace(tzinfo=timezone.utc).isoformat()
            users[user.id] = {
                'username': user.username,
                'latest_message': latest_message.content,
                'profile_pic': user.profile_pic,
                'name': user.first_name + ' ' + user.last_name,
                'me': latest_message.sender_id == current_user.id,
                'read': latest_message.read if latest_message.recipient_id == current_user.id else True,
                'orig_timestamp': timestamp_utc,
                'timestamp': latest_message.timestamp.strftime('%b %d, %Y %I:%M %p'),
                'message_id': latest_message.id
            }
        else:
            users[user.id] = {
                'username': user.username,
                'profile_pic': user.profile_pic,
                'name': user.first_name + ' ' + user.last_name,
                'latest_message': None,
                'read': True,
                'timestamp': None,
                'message_id': None
            }

    sorted_users = dict(sorted(users.items(), key=lambda item: item[1]['timestamp'] or '', reverse=True))
    return render_template('chat.html', username=current_user.username, users=sorted_users)

@app.route('/messages/<string:username>')
@login_required
def get_messages(username):
    recipient = User.query.filter_by(username=username).first()
    
    if not recipient:
        return jsonify({'messages': []})

    # Check for mutual likes
    mutual_like = Like.query.filter(
        (Like.user_id == current_user.id) & (Like.profile_id == recipient.id)
    ).first() and Like.query.filter(
        (Like.user_id == recipient.id) & (Like.profile_id == current_user.id)
    ).first()

    if not mutual_like:
        return jsonify({'messages': []})

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == recipient.id)) |
        ((Message.sender_id == recipient.id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    message_list = []
    for message in messages:
        message_list.append({
            'id': message.id,
            'username': User.query.get(message.sender_id).username,
            'content': message.content,
            'timestamp': message.timestamp,
            'reply_to_id': message.reply_to_id
        })

    return jsonify({'messages': message_list})

@app.route('/generate_socket_token')
@login_required
def generate_socket_token():
    token = secrets.token_urlsafe(16)
    socket_tokens[token] = current_user.id
    return jsonify({'socket_token': token})

@app.route('/profile')
@login_required
def profile():
    user_id = request.args.get('id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            posts = Post.query.filter_by(user_id=user.id).all()
            # check if user is liked
            liked = Like.query.filter_by(user_id=current_user.id, profile_id=user.id).first()
            return render_template('other_profile.html', user=user, posts=posts, liked=liked)
        else:
            flash('User not found', 'danger')
            return redirect(url_for('dashboard'))
    else:
        posts = Post.query.filter_by(user_id=current_user.id).all()
        likes_sent = Like.query.filter_by(user_id=current_user.id).all()
        likes_sent_users = {}
        for like in likes_sent:
            user = User.query.get(like.profile_id)
            likes_sent_users[user.id] = {
                'username': user.username,
                'profile_pic': user.profile_pic,
                'name': user.first_name + ' ' + user.last_name,
                'interests': user.interests,
                'description': user.description,
                'year': user.year,
                'faculty': user.faculty,
                'id': user.id
            }

        likes_received = Like.query.filter_by(profile_id=current_user.id).all()
        likes_received_users = {}
        for like in likes_received:
            user = User.query.get(like.user_id)
            likes_received_users[user.id] = {
                'username': user.username,
                'profile_pic': user.profile_pic,
                'name': user.first_name + ' ' + user.last_name,
                'interests': user.interests,
                'description': user.description,
                'year': user.year,
                'faculty': user.faculty,
                'id': user.id
            }
        return render_template('profile.html', posts=posts, likes_sent=likes_sent_users, likes_received=likes_received_users)

@app.route('/upload_post', methods=['POST'])
@login_required
def upload_post():
    description = request.form['description']
    content = request.form['content']

    new_post = Post(description=description, content=content, user_id=current_user.id)
    db.session.add(new_post)
    db.session.commit()

    return redirect(url_for('profile'))

@app.route('/settings/profile')
@login_required
def editProfile():
    return render_template('edit_profile.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user = current_user
    user.profile_pic = request.form['profilePictureBase64']
    user.first_name = request.form['firstName']
    user.last_name = request.form['lastName']
    user.age = int(request.form['age']) if request.form['age'] else None
    user.interests = request.form['interests']
    user.description = request.form['description']
    user.year = request.form['year']
    user.faculty = request.form['faculty']

    db.session.commit()
    return redirect(url_for('profile'))

@app.route('/like', methods=['POST'])
@login_required
def like():
    data = request.get_json()
    profile_id = data.get('id')
    
    if not profile_id:
        return jsonify({'status': False, 'error': 'Profile ID is required'}), 400

    existing_like = Like.query.filter_by(user_id=current_user.id, profile_id=profile_id).first()
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        return jsonify({'status': True, "removed": True})
    
    like = Like(user_id=current_user.id, profile_id=profile_id)
    db.session.add(like)
    db.session.commit()
    return jsonify({'status': True, "removed": False})

@socketio.on('connect')
def handle_connect():
    token = request.args.get('token')
    user_id = socket_tokens.pop(token, None)

    if user_id is None:
        disconnect()
        return

    user = User.query.get(user_id)
    if user is None:
        disconnect()
        return

    join_room(user.unique_id)
    print(f'User {user.username} connected with token {token}')

@socketio.on('disconnect')
def handle_disconnect():
    user = current_user
    if user:
        leave_room(user.unique_id)
        print(f'User {user.username} disconnected')

@socketio.on('message')
def handle_message(data):
    sender = User.query.filter_by(username=data['username']).first()
    recipient = User.query.filter_by(username=data['recipient']).first()
    reply_to_id = data.get('reply_to_id')

    mutual_like = Like.query.filter(
        (Like.user_id == sender.id) & (Like.profile_id == recipient.id)
    ).first() and Like.query.filter(
        (Like.user_id == recipient.id) & (Like.profile_id == sender.id)
    ).first()

    if not mutual_like:
        return

    new_message = Message(sender_id=sender.id, recipient_id=recipient.id, content=data['message'], reply_to_id=reply_to_id)
    db.session.add(new_message)
    db.session.commit()
    timestamp_utc = new_message.timestamp.replace(tzinfo=timezone.utc).isoformat()

    message_data = {
        'username': data['username'],
        'name': sender.first_name + ' ' + sender.last_name,
        'profile_pic': sender.profile_pic,
        'message': data['message'],
        'recipient': data['recipient'],
        'reply_to_id': reply_to_id,
        'message_id': new_message.id,
        'timestamp': timestamp_utc
    }

    emit('message', message_data, room=recipient.unique_id)
    emit('message', message_data, room=sender.unique_id)

if __name__ == "__main__":
    socketio.run(app, debug=True, host='0.0.0.0', port=5500)