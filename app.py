from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'lms2025' 

db_config = {
    'host': '10.0.116.125', 
    'user': 'cs432g8',
    'password': 'X7mLpNZq',
    'database': 'cs432g8'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

@app.route('/')
def home():
    return redirect(url_for('login')) 

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    print(request.method)
    if request.method == 'POST':
        print(request.form)
        username = request.form['username']
        password = (request.form['password'])

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM login WHERE username = %s "
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        print(user)
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            print(session['username'])
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password"
    return render_template('login.html', error=error)
  
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if user already exists 
        cursor.execute('SELECT * FROM login WHERE username = %s', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))

        # Insert new user
        cursor.execute('INSERT INTO login (username, password) VALUES (%s, %s)', (username, hashed_password))
        conn.commit()

        cursor.close()
        conn.close()

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    message = ''
    if request.method == 'POST':
        name = request.form['name']
        dob = request.form['dob']
        email = request.form['email']
        contact = request.form['contact']
        program = request.form['program']
        branch = request.form['branch']
        admission = request.form['admission']
        graduation = request.form['graduation']
        username = request.form['username']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Insert into members table
            insert_member = '''
                INSERT INTO MEMBERS
                (Name, Date_of_Birth, Email, Contact_Details, Program, Branch, Year_of_Admission, Year_of_Graduation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            '''
            cursor.execute(insert_member, (name, dob, email, contact, program, branch, admission, graduation))

            # Insert into login table with typed username & hashed password
            insert_login = '''
                INSERT INTO login (username, password)
                VALUES (%s, %s)
            '''
            cursor.execute(insert_login, (username, hashed_password))

            conn.commit()
            message = 'Member and login added successfully.'

        except mysql.connector.Error as err:
            conn.rollback()
            message = f"Error: {err}"

        finally:
            cursor.close()
            conn.close()

    return render_template('add_member.html', message=message)


if __name__ == '__main__':
    app.run(debug=True)