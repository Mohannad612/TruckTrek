from flask import Flask, render_template, url_for, redirect, flash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message

# Initialize the Flask application
app = Flask(__name__)

# Set up the application configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # This sets up the SQLite database
app.config['SECRET_KEY'] = 'SecureHome'

# Initialize the database
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'crazylogic749@gmail.com'
app.config['MAIL_PASSWORD'] = 'lnws rcaa esrf djrv'  # Replace with the app password you generated

mail = Mail(app)

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False, unique=True)  # Ensure this is an email if used for sending emails
    password = db.Column(db.String(80), nullable=False)
    
    def get_token(self, expires_sec=300):
        serial = Serializer(app.config['SECRET_KEY'], expires_in=expires_sec)
        return serial.dumps({'user_id': self.id}).decode('utf-8')
    
    @staticmethod
    def verify_token(token):
        serial = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = serial.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

# Initialize the database and create tables
with app.app_context():
    db.create_all()

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define the Registration form
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=120)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

# Define the Login form
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=120)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')
    
class ResetRequestForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=120)], render_kw={"placeholder": "Email"})
    submit = SubmitField(label='Reset Password')

class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "New Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField('Change Password')

# Define the routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

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
        return redirect(url_for('login'))
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
            return redirect(url_for('login'))
    
    return render_template('change_password.html', title="Change Password", form=form)

if __name__ == "__main__":
    app.run(debug=True)
