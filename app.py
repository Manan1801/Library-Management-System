from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM login WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username'] 
            session['role'] = user['role']   
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password" 
    return render_template('login.html', error=error)


from functools import wraps   
from flask import redirect, url_for, flash  

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash("Admin access required.")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs) 
    return decorated_function

  
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/view_table/', methods=['GET', 'POST'])
@admin_required
def view_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    print("Connected to the database")

    # Get all table names
    cursor.execute("SHOW TABLES")
    table_names = [row[0] for row in cursor.fetchall()]

    selected_table = None
    columns = []
    rows = []

    if request.method == 'POST':
        selected_table = request.form.get('table_name')
        try:
            cursor.execute(f"SELECT * FROM {selected_table}")
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
        except Exception as e:
            flash(f"Error loading table {selected_table}: {e}", 'danger')

    cursor.close()
    conn.close()
    return render_template('view_table.html', table_names=table_names, selected_table=selected_table, columns=columns, rows=rows)
 

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
@admin_required
def add_member():
    if request.method == 'POST':
        name = request.form['name']
        dob = request.form['dob']
        email = request.form['email']
        contact = request.form['contact']
        program = request.form['program']
        branch = request.form['branch']
        admission_year = request.form['admission_year']
        graduation_year = request.form['graduation_year']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert into member table
        insert_member = """
            INSERT INTO MEMBERS 
            (Name, Date_of_Birth, Email, Contact_Details, Program, Branch, Year_of_Admission, Year_of_Graduation) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_member, (name, dob, email, contact, program, branch, admission_year, graduation_year))
        conn.commit()

        # Get the newly inserted Member_ID (assuming it's auto-incremented)

        # Create login credentials
        username = email  # or f"member{member_id}" or just use the name
        raw_password = "welcome123"
        hashed_password = generate_password_hash(raw_password)

        # Insert into login table
        insert_login = "INSERT INTO login (username, password) VALUES (%s, %s)"
        cursor.execute(insert_login, (username, hashed_password))
        conn.commit()

        cursor.close()
        conn.close()

        message = f"Member added successfully! Login credentials: Username = {username}, Password = {raw_password}"
        return render_template('add_member.html', message=message)

    return render_template('add_member.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/authUser', methods=['POST'])
def auth_user():
    data = request.json

    if not data or 'username' not in data or 'password' not in data:
        return {'status': 'fail', 'message': 'Missing credentials'}, 400

    username = data['username']
    password = data['password'] 

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM login WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and check_password_hash(user['password'], password):
        token = str(uuid.uuid4())  
        session['username'] = username
        session['token'] = token
        return {'status': 'success', 'token': token}, 200
    else:
        return {'status': 'fail', 'message': 'Invalid credentials'}, 401
    

@app.route('/delete_member', methods=['GET', 'POST'])
@admin_required
def delete_member():
    if request.method == 'POST':
        username = request.form['username']

        conn = get_db_connection()
        cursor = conn.cursor()

        # First delete from login table
        cursor.execute("DELETE FROM login WHERE username = %s", (username,))

        # Then delete from members table
        cursor.execute("DELETE FROM MEMBERS WHERE Email = %s", (username,))

        conn.commit()
        cursor.close()
        conn.close()

        flash('Member deleted successfully!')

    return render_template('delete_member.html')

  
@app.route('/data')
@admin_required
def data_dashboard():
    table_names = ['MEMBERS', 'login', 'BOOKS_DETAILS', 'BOOK_AVAILABILITY', 'DIGITAL_BOOKS']
    return render_template('data_dashboard.html', tables=table_names)
     

if __name__ == '__main__':
    app.run(debug=True)         