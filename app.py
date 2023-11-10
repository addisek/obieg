from flask import Flask, g, render_template, request, redirect, url_for, flash, session, make_response
import psycopg2
from werkzeug.security import generate_password_hash
from psycopg2 import sql
from flask import g
from flask_bcrypt import Bcrypt
import os
import io
from werkzeug.utils import secure_filename
from psycopg2.extras import RealDictCursor

# Konfiguracja połączenia z bazą danych PostgreSQL
db_config = {
    "user": "postgres",
    "password": "123",
    "host": "localhost",
    "port": "5432",
    "database": "login"
}


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Określenie folderu docelowego na pulpicie
desktop_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'baza')

def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(**db_config)
    return g.db

def get_user_by_id(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return user

def pobierz_dokument_z_bazy(document_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
        cursor.execute("SELECT nazwa, oid FROM documents WHERE id = %s", (document_id,))
        result = cursor.fetchone()
    return result


def pobierz_dane_pliku(loid):
    """
    Funkcja pobiera dane pliku z bazy danych na podstawie jego OID
    używając mechanizmu Large Object PostgreSQL.
    """
    conn = get_db()
    lobj = None  # Inicjalizacja zmiennej lobj przed blokiem try
    try:
        # Użyj lobj API, aby pobrać i odczytać obiekt Large Object.
        lobj = conn.lobject(loid, 'rb')
        file_data = lobj.read()
        return file_data
    except Exception as e:
        print(f"Wystąpił błąd: {e}")
        return None  # Możesz tu zdecydować, czy zwrócić None, czy rzucić wyjątek
    finally:
        # Zawsze zamknij obiekt LOB, jeśli został otwarty
        if lobj is not None:
            lobj.close()



@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    # Tutaj możesz dodać logikę wyświetlania strony głównej
    return render_template('base.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Rozpoczęcie procesu logowania")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        print(f"Logowanie użytkownika: {username}")

        conn = get_db()
        cursor = conn.cursor()
        # Dla bezpieczeństwa, dobrą praktyką jest pobranie tylko potrzebnych kolumn
        cursor.execute('SELECT id, password FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()

        # Zadeklarowanie zmiennej wcześniej, aby uniknąć błędów
        password_check = False
        if user:
            # Tutaj user[1] powinien być hasłem z bazy danych, ale sprawdź strukturę swojego wyniku
            password_check = bcrypt.check_password_hash(user[1], password)
            print(f"Hasło zgadza się: {password_check}")

        if user and password_check:
            # user[0] powinien być id użytkownika, ale ponownie - upewnij się co do struktury twojego wyniku
            session['user_id'] = user[0]
            flash('Jesteś zalogowany!', 'success')
            return redirect(url_for('menu'))
        else:
            flash('Niepoprawne dane logowania.', 'error')

    print("Zakończenie procesu logowania")
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Usuwanie user_id z sesji
    session.pop('user_id', None)
    flash('Zostałeś wylogowany.', 'success')
    return redirect(url_for('login'))


@app.route('/test_db')
def test_db():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        cursor.close()
        return 'Połączenie z bazą danych działa!'
    except Exception as e:
        return f'Błąd połączenia z bazą danych: {e}'

@app.route('/register', methods=['GET', 'POST'])
def register():
    registration_error = {}
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Haszowanie hasła przed zapisaniem do bazy danych
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = get_db()
        cursor = conn.cursor()
        try:
            # Zapytanie SQL do wstawienia nowego użytkownika
            cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
                           (username, email, hashed_password))
            conn.commit()
            flash('Rejestracja udana. Możesz się teraz zalogować.', 'success')
            return redirect(url_for('login'))
        except psycopg2.errors.UniqueViolation as e:
            conn.rollback()
            flash('Nazwa użytkownika lub email już istnieje.', 'error')
        except Exception as e:
            conn.rollback()
            flash(f'Błąd podczas rejestracji: {str(e)}', 'error')
        finally:
            cursor.close()
            return redirect(url_for('register'))
    # Jeśli żądanie jest metodą GET, wyświetl formularz rejestracji
    return render_template('register.html', registration_error=registration_error)


@app.route('/users')
def list_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email FROM users')  # Upewnij się, że ta linijka odpowiada strukturze twojej tabeli
    users_data = cursor.fetchall()
    cursor.close()
    return render_template('users_list.html', users=users_data)

@app.route('/menu')
def menu():
    if 'user_id' not in session:
        flash('Musisz się zalogować, aby zobaczyć tę stronę.', 'error')
        return redirect(url_for('login'))

    user = get_user_by_id(session['user_id'])
    if user:
        response = make_response(render_template('menu.html', user=user))
        # Dodajemy nagłówki aby zapobiec cachowaniu strony
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    else:
        flash('Nie znaleziono użytkownika.', 'error')
        return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    # Logika dla POST
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('Musisz się zalogować, aby przesłać plik.', 'error')
            return redirect(url_for('login'))

        if 'file' not in request.files:
            flash('Nie wybrano pliku.', 'error')
            return redirect(request.url)

        file = request.files.get('file')
        if file and file.filename == '':
            flash('Nie wybrano pliku.', 'error')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            document_name = request.form['document_name']
            recipient_id = request.form['recipient_id']
            file_data = file.read()
            conn = get_db()
            cursor = conn.cursor()
            try:
                # Dodanie pliku jako Large Object
                lobj = conn.lobject(0, 'wb')
                lobj.write(file_data)
                lobj_id = lobj.oid
                lobj.close()

                # Zapisanie referencji do pliku w tabeli dokumentów
                cursor.execute(
                    'INSERT INTO documents (nazwa, oid, file_type, recipient_id) VALUES (%s, %s, %s, %s)',
                    (filename, lobj_id, 'txt', recipient_id))  # Załóżmy, że zapisujemy plik tekstowy
                conn.commit()
                flash('Plik został przesłany.', 'success')
            except Exception as e:
                conn.rollback()
                flash(f'Błąd podczas przesyłania pliku: {str(e)}', 'error')
            finally:
                cursor.close()
            return redirect(request.url)

    # Logika dla GET
    if 'user_id' not in session:
        flash('Musisz się zalogować, aby zobaczyć formularz przesyłania.', 'error')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM users')  # Upewnij się, że ta linijka odpowiada strukturze twojej tabeli
    users_data = cursor.fetchall()
    cursor.close()
    return render_template('upload.html', users=users_data)


@app.route('/mojedokumenty')
def mojedokumenty():
    if 'user_id' not in session:
        flash('Musisz się zalogować, aby zobaczyć swoje dokumenty.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db()

    with conn.cursor(cursor_factory=RealDictCursor) as cursor:
        # Zakładając, że w tabeli documents jest kolumna recipient_id, która odnosi się do użytkownika
        # który ma dostęp do dokumentu.
        cursor.execute('SELECT * FROM documents WHERE recipient_id = %s', (user_id,))
        user_documents = cursor.fetchall()

    conn.close()
    return render_template('mojedokumenty.html', documents=user_documents)


from flask import Response
import io

@app.route('/download/<int:document_id>')
def download_file(document_id):
    document = pobierz_dokument_z_bazy(document_id)
    if document:
        nazwa_pliku = document['nazwa']
        plik_oid = document['oid']

        file_data = pobierz_dane_pliku(plik_oid)
        if file_data:
            return Response(
                file_data,
                mimetype="application/octet-stream",
                headers={"Content-Disposition": "attachment;filename={}".format(nazwa_pliku)}
            )
    return "Nie znaleziono dokumentu", 404





if __name__ == '__main__':
    # app.run(debug=True, use_reloader=False)
    app.run(host='0.0.0.0', port=5000)