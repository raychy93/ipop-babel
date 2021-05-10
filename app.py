from datetime import date

import login as login
from flask import Flask, render_template, redirect, url_for, request, session, flash,g, request
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf import RecaptchaField
from wtforms import StringField, PasswordField, SelectField, SubmitField, DateTimeField, FloatField, RadioField, \
    FileField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Email, Length, InputRequired, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_manager, login_required, logout_user, current_user, login_user
from flask_ckeditor import CKEditor, CKEditorField
from flask_share import Share
from flask_mail import Mail
from flask_mail import Message
from flask_babel import Babel, get_locale, gettext
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import os
from flask import abort

# CREATE INSTANCE
app = Flask(__name__)
WTF_CSRF_SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'WTF_CSRF_SECRET_KEY')
app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY')
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
ckeditor = CKEditor(app)
Bootstrap(app)
share = Share(app)
babel = Babel(app) #babel set up


#BABEL CONFIG
@babel.localeselector
def get_locale():

    #return 'es'
    return request.accept_languages.best_match(['en', 'es', 'de'])

# EMAIL CONFIGURATION
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
mail = Mail(app)


# CREATE DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///ipop.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# CREATE TABLE

user_tag = db.Table('user_tag',
                    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
                    )

project_tag = db.Table('project_tag',
                       db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
                       db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
                       )

user_introduction = db.Table('user_introduction',
                             db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                             db.Column('introduction_id', db.Integer, db.ForeignKey('introduction.id'),
                                       primary_key=True)
                             )
project_introduction = db.Table('project_introduction',
                                db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
                                db.Column('introduction_id', db.Integer, db.ForeignKey('introduction.id'),
                                          primary_key=True)
                                )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(32))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    type = db.Column(db.String(32))
    organization = db.Column(db.String(32))
    description = db.Column(db.Text)
    date = db.Column(db.String(32))
    country = db.Column(db.String(32))
    city = db.Column(db.String(32))
    subscription = db.Column(db.String(32))

    projects = db.relationship('Project', backref='user', lazy=True)
    proposals = db.relationship('Proposal', backref='user', lazy=True)
    senteois = db.relationship('Introduction', backref='user', lazy=True)

    introductions = db.relationship('Introduction', secondary=user_introduction, lazy='subquery',
                                    backref=db.backref('users', lazy=True))
    tags = db.relationship('Tag', secondary=user_tag, lazy='subquery',
                           backref=db.backref('users', lazy=True))

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    status = db.Column(db.String(32))
    stage = db.Column(db.String(32))
    trl = db.Column(db.String(32))
    city = db.Column(db.String(32))
    country = db.Column(db.String(32))
    description = db.Column(db.Text)
    date = db.Column(db.String(32))
    purpose = db.Column(db.Text)
    type_move = db.Column(db.String(32))
    budget = db.Column(db.String(32))
    presented = db.Column(db.String(32))
    attachment = db.Column(db.String(250))

    proposals = db.relationship('Proposal', backref='project', lazy=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    introductions = db.relationship('Introduction', secondary=project_introduction, lazy='subquery',
                                    backref=db.backref('projects', lazy=True))
    tags = db.relationship('Tag', secondary=project_tag, lazy='subquery',
                           backref=db.backref('projects', lazy=True))


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False, unique=True)

    def __repr__(self):
        return '<Tag %r>' % self.name


class Proposal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    status = db.Column(db.String(32))
    description = db.Column(db.Text)
    date = db.Column(db.String(32))
    type_move = db.Column(db.String(32))
    budget = db.Column(db.String(32))
    attachment = db.Column(db.String(250))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)


class Introduction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(32))
    date = db.Column(db.String(32))
    response = db.Column(db.String(300))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


db.create_all()


# CREATE FORMS

class RegisterUser(FlaskForm):
    name = StringField(label='Your username', validators=[DataRequired()])
    email = StringField(label='Your email',
                        validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField(label='Your password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(label=('Confirm Password'), validators=[DataRequired(message='*Required'),
                                                                             EqualTo('password',
                                                                                     message='Both password fields must be equal!')])
    type = SelectField(label='Your organization type',
                       choices=[('Startup', 'Startup'), ('Researcher', 'Researcher'),
                                ('Hub or Incubator', 'Innovation hub or Incubator'),
                                ('Research Center', 'Lab or Research Center'), ('Corporate', 'Corporate'),
                                ('Consulting Firm', 'Consulting Firm'),
                                ('Investment Group', 'Investment Group'), ('other organization', 'other organization')])
    organization = StringField(label="Your organization's name")
    description = CKEditorField(label="Tell us about your organization.")
    date = HiddenField()
    city = StringField(label="Your city")
    country = StringField(label="Your country")
    subscription = SelectField(label='Your subscription type',
                               choices=[('Startup - Free', 'Startup - Free'),
                                        ('Researcher - Free', 'Researcher - Free'),
                                        ('Innovation hub - Free', 'Innovation hub - Free'),
                                        ('Lab or Research Center - Free', 'Lab or Research Center - Free'),
                                        ('Corporate - Partner', 'Corporate - Partner'),
                                        ('Consulting Firm - Sponsor', 'Consulting Firm - Sponsor'),
                                        ('Investment Group - Sponsor', 'Investment Group - Sponsor')])
    recaptcha = RecaptchaField()
    submit = SubmitField("Register")


class RegisterProject(FlaskForm):
    title = StringField(label='Project name', validators=[DataRequired()])
    status = SelectField(label='The status of your project',
                         choices=[('Draft', 'Draft'), ('Open', 'Open'), ('Ongoing', 'Ongoing'),
                                  ('Close', 'Close'), ('Cancelled', 'Cancelled')])
    stage = SelectField(label='The stage of your project',
                        choices=[('Prototyping', 'Prototyping'), ('Validation', 'Validation'), ('Scaling', 'Scaling')])
    trl = SelectField(label='Technology readiness levels',
                      choices=[('4 Lab testing', '4 Lab testing'), ('5 Simulated testing', '5 Simulated testing'),
                               ('6 Prototype development', '6 Prototype development'),
                               ('7 Prototype ready', '7  Prototype ready'),
                               ('8 Prototype validated', '8 Prototype validated'),
                               ('9 Product market-ready', '9 Product market-ready')])
    city = StringField(label="City where the project will be executed")
    country = StringField(label="Country where the project will be executed")
    description = CKEditorField(label="Tell us about your project.")
    date = HiddenField()
    purpose = CKEditorField(label="What is the main deliverable of the project?")
    type_move = SelectField(label='Type of move', choices=[('Requested', 'Requested'), ('Offered', 'Offered')])
    budget = StringField(label='Amount in Canadian Dollars $:')
    presented = HiddenField()
    attachment = HiddenField()
    recaptcha = RecaptchaField()
    submit = SubmitField("Submit")


class ViewProject(FlaskForm):
    title = StringField(label='Project name', validators=[DataRequired()])
    status = SelectField(label='The status of your project',
                         choices=[('Draft', 'Draft'), ('Open', 'Open'), ('Ongoing', 'Ongoing'),
                                  ('Close', 'Close'), ('Cancelled', 'Cancelled')])
    stage = SelectField(label='The stage of your project',
                        choices=[('Prototyping', 'Prototyping'), ('Validation', 'Validation'), ('Scaling', 'Scaling')])
    trl = SelectField(label='Technology readiness levels',
                      choices=[('4 Lab testing', '4 Lab testing'), ('5 Simulated testing', '5 Simulated testing'),
                               ('6 Prototype development', '6 Prototype development'),
                               ('7 Prototype ready', '7  Prototype ready'),
                               ('8 Prototype validated', '8 Prototype validated'),
                               ('9 Product market-ready', '9 Product market-ready')])
    city = StringField(label="City where the project will be executed")
    country = StringField(label="Country where the project will be executed")
    description = CKEditorField(label="Tell us about your project.")
    date = HiddenField()
    purpose = CKEditorField(label="What is the main deliverable of the project?")
    type_move = SelectField(label='Type of move', choices=[('Requested', 'Requested'), ('Offered', 'Offered')])
    budget = StringField(label='Amount in Canadian Dollars $:')
    presented = HiddenField()
    attachment = HiddenField()
    user_id = HiddenField()


class ViewUser(FlaskForm):
    name = StringField(label='Your username', validators=[DataRequired()])
    type = SelectField(label='Your organization type',
                       choices=[('Startup', 'Startup'), ('Researcher', 'Researcher'),
                                ('Hub or Incubator', 'Innovation hub or Incubator'),
                                ('Research Center', 'Lab or Research Center'), ('Corporate', 'Corporate'),
                                ('Consulting Firm', 'Consulting Firm'),
                                ('Investment Group', 'Investment Group'), ('other organization', 'other organization')])
    organization = StringField(label="Your organization's name")
    city = StringField(label="Your city")
    country = StringField(label="Your country")


class RegisterTag(FlaskForm):
    name = StringField(label='Tags or key words', validators=[DataRequired()])
    submit = SubmitField("Tag - Submit")


class RegisterProposal(FlaskForm):
    title = StringField(label='Title of your proposal', validators=[DataRequired()])
    status = SelectField(label='The status of the proposal',
                         choices=[('Accepted', 'Accepted'), ('Rejected', 'Rejected')])
    description = CKEditorField(label="Description of your proposal.")
    date = HiddenField()
    type_move = SelectField(label='Type of move', choices=[('Requested', 'Requested'), ('Offered', 'Offered')])
    budget = StringField(label='Amount in Canadian Dollars $:')
    attachment = StringField(label='Proposal attachments')
    recaptcha = RecaptchaField()
    submit = SubmitField("Proposal - Submit")


class LoginForm(FlaskForm):
    email = StringField(label='Your email',
                        validators=[InputRequired(), Email(message='Invalid email')])
    password = PasswordField(label='Your password', validators=[InputRequired()])
    remember = BooleanField(label='Remember me')
    submit = SubmitField("Log In")


class RegisterEoi(FlaskForm):
    # type = SelectField(label='Type of your expression of interest',
    #                    choices=[('EOI Project', 'EOI Project'), ('EOI Partner', 'EOI Partner')],
    #                    validators=[DataRequired()])
    # status = SelectField(label='The status of your EOI',
    #                      choices=[('Sent', 'Sent'), ('Accepted', 'Accepted'), ('Rejected', 'Rejected'),
    #                               ('Close', 'Close'), ('Cancelled', 'Cancelled')])
    # date = StringField(label='Sent on:')
    # response = StringField(label="Response to EOI")
    type = HiddenField()
    status = HiddenField()
    date = HiddenField()
    response = StringField(label="Provide a short message")
    project_id = HiddenField()
    submit = SubmitField("Expression of Interest EOI - Submit")


class RequestResetForm(FlaskForm):
    email = StringField(label='Your email',
                        validators=[InputRequired(), Email(message='Invalid email')])
    submit = SubmitField("Request Password Reset")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is not account with that email.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField(label='Your password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(label='Confirm Password', validators=[DataRequired(message='*Required'),
                                                                             EqualTo('password')])
    submit = SubmitField('Reset Password')


# Routes
@app.route('/')
def home():
    return render_template('index.html'.format(get_locale()), logged_in=current_user.is_authenticated)


@app.route('/user_new', methods=["GET", "POST"])
def user_new():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterUser()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash(gettext("You've already signed up with that email, log in instead!"))
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            password=form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            name=form.name.data,
            status='pending',
            email=form.email.data,
            password=hash_and_salted_password,
            type=form.type.data,
            organization=form.organization.data,
            description=form.description.data,
            date=date.today().strftime("%B %d, %Y"),
            city=form.city.data,
            country=form.country.data,
            subscription=form.subscription.data
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return '''
                <script> window.alert("New user has been created!"); </script>
                <script> window.location=document.location.href="/dashboard"; </script>
                '''
    return render_template('user_register.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/user_edit', methods=['GET', 'POST'])
@login_required
def user_edit():
    user_object = User.query.get(current_user.id)
    form = RegisterUser(obj=user_object)
    if form.validate_on_submit():
        user_object.name = form.name.data
        user_object.email = form.email.data
        user_object.type = form.type.data
        user_object.organization = form.organization.data
        user_object.description = form.description.data
        user_object.city = form.city.data
        user_object.country = form.country.data
        user_object.subscription = form.subscription.data
        db.session.commit()
        return '''
                <script> window.alert("User information has been updated!"); </script>
                <script> window.location=document.referrer; </script>
                '''
    return render_template('user_edit.html', user=user_object, form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Find user by email entered
        user = User.query.filter_by(email=email).first()

        # Email doesn't exit
        if not user:
            flash(gettext("That email does not exist, please try again."))
            return redirect(url_for('login'))

        # Password incorrect
        elif not check_password_hash(pwhash=user.password, password=password):
            flash(gettext("Password incorrect, please try again"))
            return redirect(url_for('login'))

        # Email exists and password correct
        else:
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html', form=form, logged_in=current_user.is_authenticated)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@innscience.ca',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be done
'''
    mail.send(msg)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return render_template('dashboard.html')
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash(gettext('An email has been sent with instructions to reset your password', 'info'))
        return redirect(url_for('login'))

    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return render_template('dashboard.html')
    user = User.verify_reset_token(token)
    if user is None:
        flash(gettext('That is an invalid or expired token', 'warning'))
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            password=form.password.data,
            method='pbkdf2:sha256',
            salt_length=8)
        user.password = hash_and_salted_password
        db.session.commit()
        login_user(user)
        return '''
               <script> window.alert("Your password has been update"); </script>
               <script> window.location=document.location.href="/dashboard"; </script>
               '''
    return render_template('reset_token.html', title='Reset Password', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/project_new', methods=["GET", "POST"])
@login_required
def project_new():
    form = RegisterProject(user_id=current_user.id)
    if form.validate_on_submit():
        new_project = Project(
            title=form.title.data,
            status=form.status.data,
            stage=form.stage.data,
            trl=form.trl.data,
            city=form.city.data,
            country=form.country.data,
            description=form.description.data,
            date=date.today().strftime("%B %d, %Y"),
            purpose=form.purpose.data,
            type_move=form.type_move.data,
            budget=form.budget.data,
            presented=form.presented.data,
            attachment=form.attachment.data,
            user_id=current_user.id
        )
        db.session.add(new_project)
        db.session.commit()
        return redirect(url_for('home'))

    return render_template('project_register.html', form=form)


@app.route('/projects', methods=['GET'])
def projects():
    projects_list = Project.query.order_by(Project.id).all()
    return render_template('projects.html', projects=projects_list)


@app.route('/myprojects', methods=['GET'])
@login_required
def projects_my():
    projects_list = current_user.projects
    return render_template('projects_my.html', projects=projects_list)


@app.route('/project_view', methods=['GET', 'POST'])
def project_view():
    project_id = request.args.get('project_id')
    project_selected = Project.query.get(project_id)
    form_eoi = RegisterEoi()
    if project_selected:
        if current_user.is_authenticated:
            user_id = current_user.id
            user_object = User.query.get(user_id)
            projects_with_eoi = []
            if form_eoi.validate_on_submit():
                for eoi in user_object.senteois:
                    for project in eoi.projects:
                        projects_with_eoi.append(project.id)
                if project_selected.id in projects_with_eoi:
                    return '''
                       <script> window.alert("Cannot submit more than one 'Expression of Interest'!"); </script>
                       <script> window.location=document.referrer; </script>
                           '''
                if project_selected in user_object.projects:
                    return '''
                        <script> window.alert("Cannot submit 'Expression of Interest' to your Own Project!"); </script>
                        <script> window.location=document.referrer; </script>
                        '''
                else:
                    new_eoi = Introduction(
                        type='EOI Project',
                        status='Sent',
                        date=date.today().strftime("%B %d, %Y"),
                        user_id=current_user.id
                    )
                    project_selected.introductions.append(new_eoi)
                    db.session.commit()
                    return redirect(url_for('projects'))
        return render_template('project_view.html', project=project_selected, form_eoi=form_eoi)
    else:
        return render_template('404.html'), 404


@app.route('/project_edit', methods=['GET', 'POST'])
@login_required
def project_edit():
    project_id = request.args.get('project_id')
    project_selected = Project.query.get(project_id)
    form = RegisterProject(obj=project_selected)
    if project_selected in current_user.projects:
        if form.validate_on_submit():
            project_selected.title = form.title.data
            project_selected.status = form.status.data
            project_selected.stage = form.stage.data
            project_selected.trl = form.trl.data
            project_selected.city = form.city.data
            project_selected.country = form.country.data
            project_selected.description = form.description.data
            project_selected.date = form.date.data
            project_selected.purpose = form.purpose.data
            project_selected.type_move = form.type_move.data
            project_selected.budget = form.budget.data
            project_selected.presented = form.presented.data
            project_selected.attachment = form.attachment.data
            db.session.commit()
            return redirect(url_for('projects_my'))
        return render_template('project_edit.html', project=project_selected, form=form)
    else:
        return render_template('403.html'), 403


@app.route('/deleteproject')
@login_required
def project_delete():
    project_id = request.args.get('project_id')
    project_selected = Project.query.get(project_id)
    if project_selected in current_user.projects:
        db.session.delete(project_selected)
        db.session.commit()
        return redirect(url_for('projects_my'))
    else:
        return render_template('403.html'), 403


@app.route('/technologies', methods=['GET'])
def technologies():
    startup_list = User.query.filter_by(type='Startup').all()
    researchers_list = User.query.filter_by(type='Researcher').all()
    labs_list = User.query.filter_by(type='Research Center').all()
    all_technologies = researchers_list + labs_list + startup_list
    return render_template('technologies.html', technologies=all_technologies)


@app.route('/technology_view', methods=['GET', 'POST'])
def technology_view():
    technology_id = request.args.get('technology_id')
    technology_selected = User.query.get(technology_id)
    form_eoi = RegisterEoi()
    if technology_selected:
        if current_user.is_authenticated:
            user_id = current_user.id
            user_object = User.query.get(user_id)
            technologies_with_eoi = []
            if form_eoi.validate_on_submit():
                for eoi in user_object.senteois:
                    for technology in eoi.users:
                        technologies_with_eoi.append(technology.id)
                if technology_selected.id in technologies_with_eoi:
                    return '''
                        <script> window.alert("Cannot submit more than one 'Expression of Interest'!"); </script>
                        <script> window.location=document.referrer; </script>
                           '''
                if technology_selected == user_object:
                    return '''
                        <script> window.alert("Cannot submit 'Expression of Interest' to your Own User!"); </script>
                        <script> window.location=document.referrer; </script>
                        '''
                else:
                    new_eoi = Introduction(
                        type='EOI Researcher',
                        status='Sent',
                        date=date.today().strftime("%B %d, %Y"),
                        user_id=current_user.id
                    )
                    technology_selected.introductions.append(new_eoi)
                    db.session.commit()
                    return redirect(url_for('technologies'))
        return render_template('technology_view.html', technology=technology_selected, form_eoi=form_eoi)
    else:
        return render_template('404.html'), 404



@app.route('/project_tag_new', methods=["GET", "POST"])
@login_required
def project_tag_new():
    form = RegisterTag()
    project_id = request.args.get('project_id')
    project_selected = Project.query.get(project_id)
    if project_selected in current_user.projects:
        if form.validate_on_submit():
            tag = Tag.query.filter_by(name=form.name.data.lower()).first()
            if tag:
                project_selected.tags.append(tag)
                db.session.commit()
                return redirect(url_for('projects_my'))
            tag = Tag(name=form.name.data.lower())
            project_selected.tags.append(tag)
            db.session.commit()
            return redirect(url_for('projects_my'))
        return render_template('tag_register.html', form=form)
    else:
        return render_template('403.html'), 403


@app.route('/tag_project_edit', methods=['GET', 'POST'])
@login_required
def tag_project_edit():
    tag_id = request.args.get('tag_id')
    tag_selected = Tag.query.get(tag_id)
    form = RegisterTag(obj=tag_selected)
    project_tags = []
    for project in current_user.projects:
        for tag in project.tags:
            project_tags.append(tag)
    if tag_selected in current_user.tags + project_tags:
        if form.validate_on_submit():
            tag_selected.name = form.name.data.lower()
            db.session.commit()
            return redirect(url_for('projects_my'))
        return render_template('tag_register.html', form=form)
    else:
        return render_template('403.html'), 403


@app.route('/tag_project_remove')
@login_required
def tag_project_remove():
    tag_id = request.args.get('tag_id')
    tag_selected = Tag.query.get(tag_id)
    project_id = request.args.get('project_id')
    project_selected = Project.query.get(project_id)
    if project_selected in current_user.projects:
        project_selected.tags.remove(tag_selected)
        db.session.commit()
        return redirect(url_for('projects_my'))
    else:
        return render_template('403.html'), 403


@app.route('/user_tag_new', methods=['GET', 'POST'])
@login_required
def user_tag_new():
    form = RegisterTag()
    user_object = User.query.get(current_user.id)
    if user_object.id == current_user.id:
        if form.validate_on_submit():
            tag = Tag.query.filter_by(name=form.name.data).first()
            if tag:
                user_object.tags.append(tag)
                db.session.commit()
                return redirect(url_for('user_edit'))
            tag = Tag(name=(form.name.data.lower()))
            user_object.tags.append(tag)
            db.session.commit()
            return redirect(url_for('user_edit'))
        return render_template('tag_register.html', form=form)
    else:
        return render_template('403.html'), 403


@app.route('/tag_user_edit', methods=['GET', 'POST'])
@login_required
def tag_user_edit():
    tag_id = request.args.get('tag_id')
    tag_selected = Tag.query.get(tag_id)
    form = RegisterTag(obj=tag_selected)
    if tag_selected in current_user.tags:
        if form.validate_on_submit():
            tag_selected.name = form.name.data.lower()
            db.session.commit()
            return redirect(url_for('user_edit'))
        return render_template('tag_register.html', form=form)
    else:
        return render_template('403.html'), 403


@app.route('/tag_user_remove')
@login_required
def tag_user_remove():
    tag_id = request.args.get('tag_id')
    tag_selected = Tag.query.get(tag_id)
    if tag_selected in current_user.tags:
        current_user.tags.remove(tag_selected)
        db.session.commit()
        return redirect(url_for('user_edit'))
    else:
        return render_template('403.html'), 403


@app.route('/organizations', methods=['GET'])
def organizations():
    hub_list = User.query.filter_by(type='Hub or Incubator').all()
    corporate_list = User.query.filter_by(type='Corporate').all()
    consulting_list = User.query.filter_by(type='Consulting Firm').all()
    investor_list = User.query.filter_by(type='Investment Group').all()
    other_list = User.query.filter_by(type='other organization').all()
    organizations_list = hub_list + corporate_list + consulting_list + investor_list + other_list
    return render_template('organizations.html', organizations=organizations_list)


@app.route('/organization_view', methods=['GET', 'POST'])
def organization_view():
    organization_id = request.args.get('organization_id')
    organization_selected = User.query.get(organization_id)
    form_eoi = RegisterEoi()
    if organization_selected:
        if current_user.is_authenticated:
            user_id = current_user.id
            user_object = User.query.get(user_id)
            organizations_with_eoi = []
            if form_eoi.validate_on_submit():
                for eoi in user_object.senteois:
                    for organization in eoi.users:
                        organizations_with_eoi.append(organization.id)
                if organization_selected.id in organizations_with_eoi:
                    return '''
                        <script> window.alert("Cannot submit more than one 'Expression of Interest'!"); </script>
                        <script> window.location=document.referrer; </script>
                           '''
                if organization_selected == user_object:
                    return '''
                        <script> window.alert("Cannot submit 'Expression of Interest' to your Own User!"); </script>
                        <script> window.location=document.referrer; </script>
                        '''
                else:
                    new_eoi = Introduction(
                        type='EOI Organization',
                        status='Sent',
                        date=date.today().strftime("%B %d, %Y"),
                        user_id=current_user.id
                    )
                    organization_selected.introductions.append(new_eoi)
                    db.session.commit()
                    return redirect(url_for('organizations'))
        return render_template('organization_view.html', organization=organization_selected, form_eoi=form_eoi)
    else:
        return render_template('404.html'), 404


@app.route('/myintroductions', methods=["GET", "POST"])
@login_required
def myintroductions():
    eoi_project_received = []
    myprojects_list = current_user.projects
    form = RegisterEoi()
    for project in myprojects_list:
        for eoi in project.introductions:
            eoi_project_received.append(eoi)
    eoi_user_received = current_user.introductions
    eoi_user_sent = []
    eoi_project_sent = []
    for eoi in current_user.senteois:
        if eoi.users:
            eoi_user_sent.append(eoi)
        elif eoi.projects:
            eoi_project_sent.append(eoi)
    return render_template('introductions_my.html', eoi_user_received=eoi_user_received, eoi_user_sent=eoi_user_sent,
                           eoi_project_received=eoi_project_received, eoi_project_sent=eoi_project_sent, form=form)


@app.route('/editeoi', methods=['GET', 'POST'])
@login_required
def eoi_edit():
    eoi_id = request.args.get('eoi_id')
    eoi_selected = Introduction.query.get(eoi_id)
    form = RegisterEoi(obj=eoi_selected)
    eoi_project_received = []
    for project in current_user.projects:
        for eoi in project.introductions:
            eoi_project_received.append(eoi)
    if eoi_selected in current_user.introductions + eoi_project_received:
        if form.validate_on_submit():
            eoi_selected.status = form.status.data
            eoi_selected.response = form.response.data
            db.session.commit()
            return redirect(url_for('myintroductions'))
        return render_template('eoi_edit.html', form=form)
    return render_template('403.html'), 403


@app.route('/deleteeoi')
@login_required
def eoi_delete():
    eoi_id = request.args.get('eoi_id')
    eoi_selected = Introduction.query.get(eoi_id)
    eoi_project_received = []
    for project in current_user.projects:
        for eoi in project.introductions:
            eoi_project_received.append(eoi)
    if eoi_selected in current_user.introductions + eoi_project_received + current_user.senteois:
        db.session.delete(eoi_selected)
        db.session.commit()
        return '''
                <script> window.alert("'Expression of Interest' deleted!"); </script>
                <script> window.location=document.referrer; </script>
                '''
    else:
        return render_template('403.html'), 403



@app.route('/proposal_new', methods=["GET", "POST"])
@login_required
def proposal_new():
    eoi_id = request.args.get('eoi_id')
    eoi_selected = Introduction.query.get(eoi_id)
    project_id = request.args.get('project_id')
    project_selected = Project.query.get(project_id)
    projects_proposed = []
    for proposal in current_user.proposals:
        projects_proposed.append(proposal.project)
    form_project = ViewProject(obj=project_selected)
    form = RegisterProposal()
    if form.validate_on_submit():
        if eoi_selected.status == "Accepted":
            if project_selected in projects_proposed:
                return '''
                    <script> window.alert("Cannot submit more than one 'Proposal'!"); </script>
                    <script> window.location=document.referrer; </script>
                    '''
            else:
                new_proposal = Proposal(
                    title=form.title.data,
                    status=form.status.data,
                    description=form.description.data,
                    date=form.date.data,
                    type_move=form.type_move.data,
                    budget=form.budget.data,
                    attachment=form.attachment.data,
                    user_id=current_user.id,
                    project_id=project_selected.id
                )
                db.session.add(new_proposal)
                db.session.commit()
                return redirect(url_for('home'))
        return '''
            <script> window.alert("Your EOI to this project is not accepted!"); </script>
            <script> window.location=document.referrer; </script>
            '''

    return render_template('proposal_register.html', form=form, form_project=form_project)


@app.route('/proposals_my', methods=['GET', 'POST'])
@login_required
def proposals_my():
    proposals_sent = current_user.proposals
    proposals_received = []
    my_projects = current_user.projects
    for project in my_projects:
        for proposals in project.proposals:
            proposals_received.append(proposals)
    return render_template('proposals_my.html', proposals_sent=proposals_sent, proposals_received=proposals_received)


@app.route('/proposal_respond', methods=['GET', 'POST'])
@login_required
def proposal_respond():
    proposal_id = request.args.get('proposal_id')
    proposal_selected = Proposal.query.get(proposal_id)
    form = RegisterProposal(obj=proposal_selected)
    if form.validate_on_submit():
        proposal_selected.status = form.status.data
        db.session.commit()
        return redirect(url_for('proposals_my'))
    return render_template('proposal_respond.html', form=form)


@app.route('/proposal_delete')
@login_required
def proposal_delete():
    proposal_id = request.args.get('proposal_id')
    proposal_selected = Proposal.query.get(proposal_id)
    db.session.delete(proposal_selected)
    db.session.commit()
    return '''
        <script> window.alert("Proposal deleted"); </script>
        <script> window.location=document.referrer; </script>
        '''


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
