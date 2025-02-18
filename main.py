from flask import Flask, Response, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from selenium_driverless import webdriver
from selenium_driverless.webdriver import ChromeOptions as Options
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True, nullable=False)
	password_hash = db.Column(db.String(120), nullable=False)
	projects = db.relationship('Project', backref='user', lazy=True)

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password_hash, password)


class Project(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(100), nullable=False)
	code = db.Column(db.Text, nullable=False)
	settings = db.Column(db.JSON, nullable=True)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	files = db.Column(db.JSON, nullable=True, default={}) # Added files field


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


def selenium_task():
	options = Options()()
	options.add_argument("--headless")
	options.add_argument("--disable-gpu")
	options.add_argument("--no-sandbox")
	options.add_argument("--disable-dev-shm-usage")
	driver = webdriver.Chrome(options=options)
	driver.get("http://www.python.org")
	assert "Python" in driver.title
	page_source = driver.page_source
	driver.close()
	return page_source


@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']

		if User.query.filter_by(username=username).first():
			flash('Username already exists')
			return redirect(url_for('register'))

		user = User(username=username,
		            password_hash=generate_password_hash(password))
		user.set_password(password)
		db.session.add(user)
		db.session.commit()

		return redirect(url_for('login'))
	return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		user = User.query.filter_by(username=username).first()

		if user and user.check_password(password):
			login_user(user)
			return redirect(url_for('dashboard'))
		flash('Invalid username or password')
	return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
	result = request.args.get('result', None)
	user = current_user
	projects = user.projects
	return render_template('dashboard.html', result=result, projects=projects)


@app.route('/selenium')
@login_required
def selenium_endpoint():
	try:
		selenium_task()
		flash('Selenium task executed successfully!', 'success')
		return redirect(
		    url_for('dashboard', result="Successfully scraped Python.org"))
	except Exception as e:
		flash(f'Error executing selenium task: {str(e)}', 'error')
		return redirect(url_for('dashboard', result=f"Error: {str(e)}"))


@app.route('/')
def index():
	return render_template('index.html')


@app.route('/project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def project(project_id):
	project = Project.query.get_or_404(project_id)
	if request.method == 'POST':
		if 'name' in request.form:
			project.name = request.form['name']
		if 'code' in request.form:
			project.code = request.form['code']
		if 'settings' in request.form:
			try:
				project.settings = json.loads(request.form['settings'])
			except json.JSONDecodeError:
				flash('Invalid JSON settings', 'error')
		if 'files' in request.form:
			try:
				project.files = json.loads(request.form['files'])
			except json.JSONDecodeError:
				flash('Invalid JSON files', 'error')
		db.session.commit()
		flash('Project updated successfully!', 'success')
		return redirect(url_for('dashboard'))
	return render_template('project.html', project=project)


@app.route('/new_project', methods=['POST'])
@login_required
def new_project():
	if 'code' not in request.files:
		flash('No file uploaded', 'error')
		return redirect(url_for('dashboard'))

	file = request.files['code']
	name = request.form.get('name', '')

	if file.filename == '':
		flash('No selected file', 'error')
		return redirect(url_for('dashboard'))

	try:
		code = file.read().decode('utf-8')
		project = Project(name=name,
		                  code=code,
		                  settings={
		                      'browser': 'chrome',
		                      'headless': True,
                              'use_proxy': False,
                              'proxy_address': '',
                              'thread_count': 1
		                  },
		                  user=current_user)
		db.session.add(project)
		db.session.commit()
		flash('Project created successfully!', 'success')
	except Exception as e:
		flash(f'Error creating project: {str(e)}', 'error')

	return redirect(url_for('dashboard'))


@app.route('/project/<int:id>/files', methods=['GET'])
@login_required
def get_project_files(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        return {'error': 'Unauthorized'}, 403
    return project.files

@app.route('/project/<int:id>/edit', methods=['POST'])
@login_required
def edit_project(id):
    project = Project.query.get_or_404(id)

    if project.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))

    files = request.form.get('files', '{}')
    try:
        project.files = json.loads(files)
        db.session.commit()
        flash('Project updated successfully!', 'success')
    except json.JSONDecodeError:
        flash('Invalid JSON files', 'error')
    return redirect(url_for('dashboard'))


@app.route('/project/<int:id>/settings', methods=['POST'])
@login_required
def update_settings(id):
	project = Project.query.get_or_404(id)

	if project.user_id != current_user.id:
		return {'error': 'Unauthorized'}, 403

	try:
		settings = request.get_json()
		project.settings = settings
		db.session.commit()
		return {'message': 'Settings updated'}, 200
	except Exception as e:
		return {'error': str(e)}, 400


@app.route('/settings/<int:project_id>', methods=['GET', 'POST'])
@login_required
def settings(project_id):
	project = Project.query.get_or_404(project_id)
	if request.method == 'POST':
		try:
			project.settings = json.loads(request.form['settings'])
			db.session.commit()
			flash('Settings updated successfully!', 'success')
		except json.JSONDecodeError:
			flash('Invalid JSON settings', 'error')
	return render_template('settings.html', project=project)


if __name__ == '__main__':
	with app.app_context():
		db.create_all()
	app.run(debug=True,host='0.0.0.0')