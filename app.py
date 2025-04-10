from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask import  request, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from session_utils import log_unauthorized_access

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

def is_admin(session_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # First get the username linked to this session
    cursor.execute("SELECT username FROM sessions WHERE session_id = %s", (session_id,))
    result = cursor.fetchone()

    if result:
        username = result[0]
        # Now check if this user is admin
        cursor.execute("SELECT role FROM login WHERE username = %s", (username,))
        role_result = cursor.fetchone()
        conn.close()
        if role_result and role_result[0] == 'admin':
            return True

    conn.close()
    return False


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

        if user and check_password_hash(user['password'], password):
            session_id = str(uuid.uuid4())
            
            cursor.execute("INSERT INTO sessions (username, session_id,role) VALUES (%s, %s,%s)", (username, session_id,user['role']))
            conn.commit()

            session['username'] = user['username']
            session['role'] = user['role']
            session['session_id'] = session_id  # store in Flask session

            cursor.close()
            conn.close()
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password"
            cursor.close()
            conn.close()
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

def isValidSession(session_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sessions WHERE session_id = %s", (session_id,))
    result = cursor.fetchone()
    conn.close()
    # print("Session ID:", session_id)
    # print(result)
    return result is not None

@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data['username']
    password = data['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM login WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()

    if user:
        session_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO sessions (username, session_id) VALUES (?, ?)", (username, session_id))
        conn.commit()
        conn.close()
        return jsonify({'session_id': session_id}), 200
    else:
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    

@app.route('/books', methods=['POST'])
def ADD_book():
    data = request.get_json()
    session_id = request.headers.get('Session-ID')

    print("Headers:", request.headers)
    print("JSON Body:", request.get_json())


    # Session check
    print("Session ID:", session_id)
    # print(isValidSession(session_id))
    # print(is_admin(session_id))
    if not isValidSession(session_id) or not is_admin(session_id):
        log_unauthorized_access("POST /books", "add_book")
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()

    # Get book fields
    name = data.get('Book_Name')
    author = data.get('Book_Author')
    year = data.get('Book_Publication_Year')
    reviews = data.get('Total_Reviews', 0)  # Default to 0 if not provided
    quantity = data.get('Quantity')
    genre = data.get('BOOK_GENRE')

    # Insert into DB
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO BOOKS_DETAILS
            (Book_Name, Book_Author, Book_Publication_Year, Total_Reviews, Quantity, BOOK_GENRE) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (name, author, year, reviews, quantity, genre))

        conn.commit()
        conn.close()
        return jsonify({'message': 'Book added successfully'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/borrow/<int:book_id>', methods=['POST'])
def borrow_book(book_id):
    session_id = request.headers.get('Session-ID')

    if not isValidSession(session_id):
        log_unauthorized_access("POST /borrow", f"book_id={book_id}")
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check current quantity
        cursor.execute("SELECT Quantity_Remaining FROM BOOK_AVAILABILITY WHERE BookID = %s", (book_id,))
        result = cursor.fetchone()

        if not result:
            conn.close()
            return jsonify({'error': 'Book not found'}), 404

        quantity = result[0]

        if quantity <= 0:
            conn.close()
            return jsonify({'error': 'Book not available'}), 400

        # Update quantity
        new_quantity = quantity - 1
        availability = 'Available' if new_quantity > 0 else 'Not Available'

        cursor.execute("""
            UPDATE BOOK_AVAILABILITY
            SET Quantity_Remaining = %s, Availability = %s
            WHERE BookID = %s
        """, (new_quantity, availability, book_id))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Book borrowed successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/books', methods=['GET'])
def get_books():
    session_id = request.headers.get('Session-ID')
    if not isValidSession(session_id):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM BOOKS_DETAILS")
    books = cursor.fetchall()
    conn.close()
    return jsonify(books), 200



@app.route('/books/<int:book_id>', methods=['PUT'])
def update_book(book_id):
    session_id = request.headers.get('Session-ID')

    if not isValidSession(session_id) or not is_admin(session_id):
        log_unauthorized_access("PUT /books", "update_book")
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        fields = []
        values = []

        for key in ['Book_Name', 'Book_Author', 'Book_Publication_Year', 'Total_Reviews', 'Quantity', 'BOOK_GENRE']:
            if key in data:
                fields.append(f"{key} = %s")
                values.append(data[key])

        if not fields:
            return jsonify({'error': 'No fields to update'}), 400

        values.append(book_id)
        query = f"UPDATE BOOKS_DETAILS SET {', '.join(fields)} WHERE Book_ID = %s"
        cursor.execute(query, tuple(values)) 

        conn.commit()
        conn.close()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Book not found'}), 404

        return jsonify({'message': 'Book updated successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/notifications', methods=['POST'])
def send_notification():
    data = request.get_json()
    session_id = request.headers.get('Session-ID')

    if not isValidSession(session_id) or not is_admin(session_id):
        log_unauthorized_access("POST /notifications", "send_notification")
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO NOTIFICATIONS (Member_ID, Message, Notification_Date, Type)
            VALUES (%s, %s, NOW(), %s)
        """, (data['Member_ID'], data['Message'], data['Type']))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Notification sent successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/reserve', methods=['POST'])
def reserve_book():
    data = request.get_json()
    session_id = request.headers.get('Session-ID')

    if not isValidSession(session_id):
        log_unauthorized_access("POST /reserve", "reserve_book")
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Default reservation expiry: 7 days from today
        cursor.execute("""
            INSERT INTO RESERVATIONS (Member_ID, Book_ID, Reservation_Date, Expiry_Date, Status)
            VALUES (%s, %s, CURDATE(), DATE_ADD(CURDATE(), INTERVAL 7 DAY), 'Active')
        """, (data['Member_ID'], data['Book_ID']))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Book reserved successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)            