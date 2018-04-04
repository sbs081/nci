from flask import Flask, render_template, flash , redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route('/')
def index():
    return render_template('index.html')

# @app.route('/about')
# def about():
#     return render_template('about.html')

@app.route('/domains')
@is_logged_in
def domains():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM domains")

    domains = cur.fetchall()

    if result > 0:
        return render_template('domains.html', domains=domains)
    else:
        msg = 'No Domains Found'
        return render_template('domains.html', msg=msg)
    # Close connection
    cur.close()


@app.route('/domain/<string:id>/')
@is_logged_in
def domain(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM domains WHERE id = %s", [id])

    domain = cur.fetchone()
    return render_template('domain.html', domain=domain)

# RegisterForm Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

# User Register
@app.route('/register', methods=['GET', 'POST'])
def regiser():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO users(name, email, username, password) "
                    "VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'PASSWORD NOT MATCHED'
                return render_template('login.html', error=error)
            # Close connection
            cur.close
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM domains")

    domains = cur.fetchall()

    if result > 0:
        return render_template('dashboard.html', domains=domains)
    else:
        msg = 'No Articles Found'
        return render_template('dashboard.html', msg=msg)
    # Close connection
    cur.close()



# Domain Form Class
class DomainForm(Form):
    domain = StringField('域名:')
    port = StringField('端口:')
    route = StringField('路径:')
    proxy = TextAreaField('proxy_set_header模版,一般不需要改动',
                          default="proxy_set_header Host $host;proxy_set_header X-Real-IP $remote_addr;proxy_set_header X-Forwarded-For $http_x_forwarded_for;")
    location = TextAreaField('自定义location(默认为空,谨慎添加,配置错误可能导致无法reload)')


# Add Domain
@app.route('/add_domain', methods=['GET', 'POST'])
@is_logged_in
def add_doomain():
    form = DomainForm(request.form)
    if request.method == 'POST' and form.validate():
        domain = request.form['domain']
        port = request.form['port']
        route = request.form['route']
        proxy = request.form['proxy']
        location = request.form['location']
        body = "test"

        # Create Cursor
        cur = mysql.connection.cursor()

        # Excute
        cur.execute("INSERT INTO domains (domain, port, route, proxy, location, body, createuser) VALUES(%s, %s, %s, %s, %s, %s, %s)", (domain, port, route, proxy, location, body, session['username']))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Domain Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_domain.html', form=form)

# Edit Article
@app.route('/edit_domain/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_domain(id):
    # Create Cursor
    cur = mysql.connection.cursor()

    # Get article by id
    result = cur.execute("SELECT * FROM domains WHERE id = %s", [id])

    domain = cur.fetchone()

    # Get fom
    form = DomainForm(request.form)

    # Populate article form fields
    form.domain.data = domain['domain']
    form.port.data = domain['port']
    form.route.data = domain['route']
    form.proxy.data = domain['proxy']
    form.location.data = domain['location']

    if request.method == 'POST' and form.validate():
        domain = request.form['domain']
        port = request.form['port']
        route = request.form['route']
        proxy = request.form['proxy']
        location = request.form['location']


        # Create Cursor
        cur = mysql.connection.cursor()

        # Excute
        cur.execute("UPDATE domains SET domain=%s, port=%s , route=%s, proxy=%s, location=%s WHERE id = %s", (domain, port, route, proxy, location, id))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Domain Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_domains.html', form=form)

# Delete Article
@app.route('/delete_domain/<string:id>', methods=['POST'])
@is_logged_in
def delete_domain(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM domains WHERE id =%s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()


    flash('Domain Deleted', 'success')

    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)
