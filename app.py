# app.py - Dashboard PI com MFA Microsoft/Google Authenticator
# Mantém todas as funcionalidades originais + autenticação segura

from flask import Flask, render_template_string, send_from_directory, abort, session, redirect, url_for, request, flash
import pandas as pd
import numpy as np
from matplotlib.figure import Figure
import io
import base64
import os
from typing import Optional
import pyotp
import qrcode
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET", "dashboard-pi-secret-key-2024-change-in-production")

# ========== SISTEMA DE USUÁRIOS COM MFA ==========
# Para produção, use um banco de dados. Aqui usamos memória para demonstração.
users = {
    # Usuário administrador padrão (senha: admin123)
    "admin": {
        "password": generate_password_hash("admin123"),
        "mfa_secret": pyotp.random_base32(),
        "registered_at": datetime.utcnow().isoformat(),
        "last_login": None,
        "login_count": 0,
        "logged_in": False
    }
}

# ========== CONFIGURAÇÃO DO DASHBOARD ==========
ROOT = os.path.abspath(os.path.dirname(__file__))
CSV_FILENAME = "leituras_sala_de_aula.csv"
HTML_FILENAME = "dashboard_ui.html"

CSV_PATH = os.path.join(ROOT, CSV_FILENAME)
HTML_PATH = os.path.join(ROOT, HTML_FILENAME)

# Carregar dados CSV
if not os.path.exists(CSV_PATH):
    raise FileNotFoundError(f"Arquivo CSV não encontrado: {CSV_PATH}")

df = pd.read_csv(CSV_PATH)

# Pré-processamento básico
if "timestamp" in df.columns:
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.sort_values("timestamp").reset_index(drop=True)

# Corrigir anomalia em lux_max
if "lux_min" in df.columns and "lux_max" in df.columns:
    bad_mask = (df["lux_max"] < 10) | (df["lux_max"] < df["lux_min"])
    if bad_mask.any():
        df.loc[bad_mask, "lux_max"] = df.loc[bad_mask, "lux_min"]

# Garantir colunas numéricas
for col in ["temp_min", "temp_max", "temp_avg", "lux_min", "lux_max", "lux_avg"]:
    if col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")

# ========== FUNÇÕES AUXILIARES ==========

def fig_to_base64(fig: Figure) -> str:
    """Converte figura matplotlib para base64 PNG."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight")
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode("utf-8")
    try:
        fig.clf()
        del fig
    except Exception:
        pass
    return b64

def scatter_with_regression_base64(x: np.ndarray, y: np.ndarray, xlabel: str, ylabel: str, title: str) -> Optional[str]:
    """Cria scatter plot com regressão linear."""
    mask = (~np.isnan(x)) & (~np.isnan(y))
    x_clean = x[mask]
    y_clean = y[mask]
    if x_clean.size == 0:
        return None
    
    corr = np.corrcoef(x_clean, y_clean)[0, 1]
    m, b = np.polyfit(x_clean, y_clean, 1)
    
    fig = Figure(figsize=(6, 4))
    ax = fig.subplots()
    ax.scatter(x_clean, y_clean, alpha=0.75, edgecolors="k", label="leituras")
    x_line = np.linspace(x_clean.min(), x_clean.max(), 100)
    y_line = m * x_line + b
    ax.plot(x_line, y_line, color="red", linewidth=2, label=f"tendência: y={m:.2f}x+{b:.1f}")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(f"{title} - Pearson = {corr:.3f}")
    ax.legend()
    
    return fig_to_base64(fig)

def qrcode_data_url(data: str) -> str:
    """Gera QR Code como data URL."""
    img = qrcode.make(data)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{b64}"

@app.template_filter('shorttime')
def shorttime(s: str) -> str:
    """Filtro para formatar datas."""
    if not s:
        return "-"
    try:
        dt = datetime.fromisoformat(s)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return s

# ========== DECORATOR DE PROTEÇÃO ==========

def login_required(f):
    """Decorator para proteger rotas que requerem autenticação MFA."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (session.get('username') and session.get('mfa_validated')):
            flash('🔒 Acesso negado. Faça login e valide o MFA primeiro.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ========== ROTAS DE AUTENTICAÇÃO ==========

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login."""
    if session.get('username') and session.get('mfa_validated'):
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        
        user = users.get(username)
        if not user or not check_password_hash(user['password'], password):
            flash('❌ Usuário ou senha inválidos.', 'danger')
            return redirect(url_for('login'))
        
        # Salvar na sessão
        session['username'] = username
        session['mfa_validated'] = False
        
        # SEMPRE mostrar QR Code se for primeiro acesso ou não tiver secret
        if not user.get('mfa_secret'):
            user['mfa_secret'] = pyotp.random_base32()
        
        # Gerar QR Code para Microsoft Authenticator
        secret = user['mfa_secret']
        url = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, 
            issuer_name="Dashboard PI"
        )
        img_url = qrcode_data_url(url)
        
        # Página de configuração MFA
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Configurar MFA - Dashboard PI</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <style>
                    body { background: #f8f9fa; padding-top: 50px; }
                    .card { max-width: 500px; margin: auto; }
                </style>
            </head>
            <body>
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0">🔐 Configure seu Microsoft Authenticator</h4>
                    </div>
                    <div class="card-body">
                        <p>Usuário: <strong>{{ username }}</strong></p>
                        
                        <div class="text-center my-4">
                            <img src="{{ img_url }}" alt="QR Code" class="img-fluid" style="max-width: 250px;">
                            <p class="mt-2">Chave secreta: <code>{{ secret }}</code></p>
                        </div>
                        
                        <div class="alert alert-success">
                            <h6>✅ Passo a Passo:</h6>
                            <ol class="mb-0">
                                <li><strong>Abra o Microsoft Authenticator</strong> no seu celular</li>
                                <li>Toque no <strong>"+"</strong> (canto superior direito)</li>
                                <li>Selecione <strong>"Outra conta (Google, Facebook, etc.)"</strong></li>
                                <li><strong>Escaneie o QR Code acima</strong> com a câmera</li>
                                <li>A conta será adicionada automaticamente</li>
                                <li>Volte aqui e clique em <strong>"Continuar para Login"</strong></li>
                            </ol>
                        </div>
                        
                        <div class="text-center mt-4">
                            <a href="{{ url_for('mfa_verify') }}" class="btn btn-success btn-lg">
                                ✅ Já escaneei - Continuar para Login
                            </a>
                            <br>
                            <small class="text-muted mt-2 d-block">
                                Problemas? <a href="#" onclick="alert('Tente digitar a chave manualmente no app: {{ secret }}')">Ver chave manual</a>
                            </small>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''', img_url=img_url, secret=secret, username=username)
    
    # Página de login HTML
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="pt-br">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login - Dashboard PI</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: #f8f9fa; min-height: 100vh; display: flex; align-items: center; }
                .login-card { max-width: 400px; margin: auto; padding: 2rem; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
                .logo { font-size: 2.5rem; color: #0d6efd; margin-bottom: 1rem; }
            </style>
        </head>
        <body>
            <div class="login-card bg-white">
                <div class="text-center mb-4">
                    <div class="logo">📊</div>
                    <h2>Dashboard PI</h2>
                    <p class="text-muted">Autenticação com Microsoft Authenticator</p>
                </div>
                
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Usuário</label>
                        <input type="text" class="form-control" name="username" required autofocus value="admin">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Senha</label>
                        <input type="password" class="form-control" name="password" required value="admin123">
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Entrar</button>
                </form>
                
                <div class="text-center mt-3">
                    <small>Credenciais teste: <strong>admin</strong> / <strong>admin123</strong></small><br>
                    <a href="{{ url_for('register') }}">Criar nova conta</a>
                </div>
            </div>
        </body>
        </html>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Página de registro de novo usuário."""
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        
        if not username or not password:
            flash('⚠️ Usuário e senha são obrigatórios.', 'warning')
            return redirect(url_for('register'))
        
        if username in users:
            flash('⚠️ Usuário já existe.', 'warning')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('⚠️ Senha deve ter pelo menos 6 caracteres.', 'warning')
            return redirect(url_for('register'))
        
        # Criar novo usuário com MFA
        secret = pyotp.random_base32()
        users[username] = {
            'password': generate_password_hash(password),
            'mfa_secret': secret,
            'registered_at': datetime.utcnow().isoformat(),
            'last_login': None,
            'login_count': 0,
            'logged_in': False
        }
        
        # Gerar QR Code para Microsoft/Google Authenticator
        url = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, 
            issuer_name="Dashboard PI"
        )
        img_url = qrcode_data_url(url)
        
        # Página de configuração MFA
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Configurar MFA</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <style>
                    body { background: #f8f9fa; padding-top: 50px; }
                    .card { max-width: 500px; margin: auto; }
                </style>
            </head>
            <body>
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0">✅ Registro Concluído!</h4>
                    </div>
                    <div class="card-body">
                        <h5>Configure o Microsoft/Google Authenticator</h5>
                        <p>Usuário: <strong>{{ username }}</strong></p>
                        
                        <div class="text-center my-4">
                            <img src="{{ img_url }}" alt="QR Code" class="img-fluid" style="max-width: 250px;">
                            <p class="mt-2">Chave secreta: <code>{{ secret }}</code></p>
                        </div>
                        
                        <div class="alert alert-info">
                            <h6>📱 Como configurar:</h6>
                            <ol class="mb-0">
                                <li>Abra o <strong>Microsoft Authenticator</strong> ou <strong>Google Authenticator</strong></li>
                                <li>Toque em <strong>"+"</strong> → <strong>"Adicionar conta"</strong></li>
                                <li>Escaneie o QR Code acima</li>
                                <li>Guarde a chave secreta em local seguro</li>
                                <li>Use os códigos de 6 dígitos para fazer login</li>
                            </ol>
                        </div>
                        
                        <div class="text-center mt-4">
                            <a href="{{ url_for('login') }}" class="btn btn-success btn-lg">
                                🚀 Ir para Login
                            </a>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''', img_url=img_url, secret=secret, username=username)
    
    # Página de registro HTML
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Registrar - Dashboard PI</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="container mt-5">
            <div class="card" style="max-width: 400px; margin: auto;">
                <div class="card-body">
                    <h3 class="text-center">📝 Criar Conta</h3>
                    
                    {% with messages = get_flashed_messages(with_categories=true) %}
                        {% if messages %}
                            {% for category, message in messages %}
                                <div class="alert alert-{{ category }}">{{ message }}</div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    
                    <form method="POST">
                        <div class="mb-3">
                            <label>Usuário</label>
                            <input type="text" class="form-control" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label>Senha (mínimo 6 caracteres)</label>
                            <input type="password" class="form-control" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Registrar</button>
                    </form>
                    
                    <div class="text-center mt-3">
                        <a href="{{ url_for('login') }}">Já tem conta? Faça login</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
    ''')

@app.route('/mfa_verify', methods=['GET', 'POST'])
def mfa_verify():
    """Validação do código MFA."""
    username = session.get('username')
    if not username:
        flash('⚠️ Faça login primeiro.', 'warning')
        return redirect(url_for('login'))
    
    user = users.get(username)
    if not user:
        session.clear()
        flash('❌ Usuário não encontrado.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip().replace(' ', '')
        
        if not code or len(code) != 6 or not code.isdigit():
            flash('❌ Código deve ter 6 dígitos numéricos.', 'danger')
            return redirect(url_for('mfa_verify'))
        
        totp = pyotp.TOTP(user['mfa_secret'])
        
        if totp.verify(code, valid_window=1):
            # MFA validado com sucesso!
            session['mfa_validated'] = True
            
            # Atualizar estatísticas do usuário
            user['last_login'] = datetime.utcnow().isoformat()
            user['login_count'] = user.get('login_count', 0) + 1
            user['logged_in'] = True
            
            flash('✅ Autenticação MFA validada com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('❌ Código inválido ou expirado. Tente novamente.', 'danger')
            return redirect(url_for('mfa_verify'))
    
    # Página de verificação MFA
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Verificar MFA - Dashboard PI</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: #f8f9fa; padding-top: 50px; }
                .code-input { font-size: 2rem; letter-spacing: 10px; text-align: center; }
                .card { max-width: 400px; margin: auto; }
            </style>
        </head>
        <body>
            <div class="card">
                <div class="card-header bg-info text-white">
                    <h4 class="mb-0">🔐 Verificação em Duas Etapas</h4>
                </div>
                <div class="card-body text-center">
                    <p>Usuário: <strong>{{ username }}</strong></p>
                    
                    <div class="alert alert-warning">
                        <h5>📱 Abra seu Authenticator</h5>
                        <p class="mb-0">Microsoft Authenticator ou Google Authenticator</p>
                    </div>
                    
                    {% with messages = get_flashed_messages(with_categories=true) %}
                        {% if messages %}
                            {% for category, message in messages %}
                                <div class="alert alert-{{ category }}">{{ message }}</div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    
                    <form method="POST">
                        <div class="mb-4">
                            <label class="form-label">Código de 6 dígitos</label>
                            <input type="text" 
                                   class="form-control code-input" 
                                   name="code" 
                                   placeholder="000000"
                                   maxlength="6"
                                   pattern="\d{6}"
                                   required
                                   autofocus>
                            <div class="form-text">
                                Digite o código do seu aplicativo autenticador
                            </div>
                        </div>
                        
                        <button type="submit" class="btn btn-primary btn-lg w-100">
                            ✅ Verificar Código
                        </button>
                    </form>
                    
                    <div class="mt-4">
                        <a href="{{ url_for('logout') }}" class="text-danger">
                            ↩️ Trocar usuário
                        </a>
                    </div>
                </div>
            </div>
            
            <script>
                // Auto-foco e validação
                document.querySelector('.code-input').addEventListener('input', function(e) {
                    this.value = this.value.replace(/[^0-9]/g, '');
                    if (this.value.length === 6) {
                        this.form.submit();
                    }
                });
            </script>
        </body>
        </html>
    ''', username=username)

@app.route('/logout')
def logout():
    """Logout do sistema."""
    username = session.get('username')
    if username and username in users:
        users[username]['logged_in'] = False
    
    session.clear()
    flash('👋 Desconectado com sucesso.', 'info')
    return redirect(url_for('login'))

# ========== ROTAS PROTEGIDAS DO DASHBOARD ==========

@app.route('/')
@login_required
def index():
    """Dashboard principal - PROTEGIDO POR MFA."""
    if os.path.exists(HTML_PATH):
        with open(HTML_PATH, 'r', encoding='utf-8') as f:
            html = f.read()
        
        # Estatísticas para o template
        stats = {
            'num_registros': int(len(df)),
            'ultima_leitura': str(df['timestamp'].max()) if 'timestamp' in df.columns else '',
            'temp_media': float(df['temp_avg'].mean()) if 'temp_avg' in df.columns else None,
            'lux_media': float(df['lux_avg'].mean()) if 'lux_avg' in df.columns else None,
            'username': session.get('username', 'Visitante')
        }
        
        # Adicionar botão de logout ao HTML
        html_modificado = html.replace(
            '</head>',
            '''<style>
                .user-info {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: white;
                    padding: 10px 15px;
                    border-radius: 20px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                    z-index: 1000;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .logout-btn {
                    background: #dc3545;
                    color: white;
                    border: none;
                    padding: 5px 10px;
                    border-radius: 5px;
                    text-decoration: none;
                    font-size: 12px;
                }
                .logout-btn:hover {
                    background: #c82333;
                }
            </style>
            </head>'''
        )
        
        # Adicionar info do usuário no body
        html_modificado = html_modificado.replace(
            '<body>',
            f'''<body>
                <div class="user-info">
                    👤 {stats['username']}
                    <a href="{{{{ url_for('logout') }}}}" class="logout-btn">Sair</a>
                </div>'''
        )
        
        return render_template_string(html_modificado, **stats)
    
    # Fallback se não encontrar HTML
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Dashboard</title></head>
    <body>
        <h2>Dashboard PI</h2>
        <p>Autenticado como: <strong>{}</strong></p>
        <ul>
            <li><a href="/medias">Médias</a></li>
            <li><a href="/contagem">Contagem Min/Max</a></li>
            <li><a href="/correlacao">Correlação</a></li>
        </ul>
        <a href="/logout">Sair</a>
    </body>
    </html>
    '''.format(session.get('username', 'Visitante'))

@app.route('/medias')
@login_required
def medias():
    """Gráfico de médias - PROTEGIDO."""
    cols = []
    if "temp_avg" in df.columns:
        cols.append("temp_avg")
    if "lux_avg" in df.columns:
        cols.append("lux_avg")
    
    if not cols:
        return "<h2>❌ Não há colunas 'temp_avg' ou 'lux_avg' no CSV.</h2>"
    
    medias = df[cols].mean()
    fig = Figure(figsize=(6, 4))
    ax = fig.subplots()
    colors = ["#4c78a8" if c == "temp_avg" else "#f58518" for c in medias.index]
    medias.plot(kind="bar", ax=ax, color=colors)
    ax.set_ylabel("Valor médio")
    ax.set_xticklabels([("Temperatura (°C)" if c == "temp_avg" else "Luminosidade (lux)") for c in medias.index], rotation=0)
    ax.set_title("Médias das Leituras")
    img = fig_to_base64(fig)
    
    html = f'''
    <div style="font-family: Inter, system-ui, Arial; padding: 20px; max-width: 800px; margin: auto;">
        <h2>📊 Médias das Leituras</h2>
        <p>Usuário: <strong>{session.get('username')}</strong> | <a href="/">Voltar</a> | <a href="/logout">Sair</a></p>
        <img src="data:image/png;base64,{img}" style="max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 8px;"/>
        <ul>
            {"".join([f"<li><b>{'Temperatura média' if c == 'temp_avg' else 'Luminosidade média'}</b>: {medias[c]:.2f}</li>" for c in medias.index])}
        </ul>
    </div>
    '''
    return html

@app.route('/contagem')
@login_required
def contagem():
    """Contagem de mínimos e máximos - PROTEGIDO."""
    metrics = []
    if "temp_min" in df.columns and "temp_max" in df.columns:
        metrics.append("temp")
    if "lux_min" in df.columns and "lux_max" in df.columns:
        metrics.append("lux")
    
    if not metrics:
        return "<h2>❌ Não há pares de colunas '_min' e '_max' para 'temp' ou 'lux' no CSV.</h2>"
    
    rows = []
    for m in metrics:
        min_col = f"{m}_min"
        max_col = f"{m}_max"
        min_val = df[min_col].min()
        max_val = df[max_col].max()
        min_count = int((df[min_col] == min_val).sum())
        max_count = int((df[max_col] == max_val).sum())
        
        rows.append({
            "metric": m,
            "min_value": float(min_val) if pd.notna(min_val) else None,
            "min_count": min_count,
            "max_value": float(max_val) if pd.notna(max_val) else None,
            "max_count": max_count
        })
    
    summary = pd.DataFrame([{"metric": r["metric"], "min_count": r["min_count"], "max_count": r["max_count"]} for r in rows]).set_index("metric")
    
    fig = Figure(figsize=(6, 4))
    ax = fig.subplots()
    summary.plot(kind="bar", ax=ax, color=["#54a24b", "#e45756"])
    ax.set_ylabel("Ocorrências")
    ax.set_title("Contagem de Mínimos e Máximos por Métrica")
    ax.legend(['Mínimos', 'Máximos'])
    ax.set_xticklabels([("Temperatura" if m == "temp" else "Luminosidade") for m in summary.index], rotation=0)
    img = fig_to_base64(fig)
    
    info_html = "<ul>"
    for r in rows:
        metric_label = "Temperatura" if r["metric"] == "temp" else "Luminosidade"
        info_html += f'''
        <li><b>{metric_label}</b>: 
            mínimo = {r["min_value"]:.2f} (ocorre {r["min_count"]}x),
            máximo = {r["max_value"]:.2f} (ocorre {r["max_count"]}x)
        </li>
        '''
    info_html += "</ul>"
    
    return f'''
    <div style="font-family: Inter, system-ui, Arial; padding: 20px; max-width: 800px; margin: auto;">
        <h2>📈 Contagem de Mínimos e Máximos</h2>
        <p>Usuário: <strong>{session.get('username')}</strong> | <a href="/">Voltar</a> | <a href="/logout">Sair</a></p>
        <img src="data:image/png;base64,{img}" style="max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 8px;"/>
        {info_html}
    </div>
    '''

@app.route('/correlacao')
@login_required
def correlacao():
    """Correlação temperatura vs luminosidade - PROTEGIDO."""
    plots_html = ""
    
    # temp_avg vs lux_avg
    if "temp_avg" in df.columns and "lux_avg" in df.columns:
        x = df['temp_avg'].to_numpy(dtype=float)
        y = df['lux_avg'].to_numpy(dtype=float)
        img_b64 = scatter_with_regression_base64(x, y, "Temperatura média (°C)", "Luminosidade média (lux)", "Temp_avg × Lux_avg")
        if img_b64:
            plots_html += f'<h3>📈 Temperatura média × Luminosidade média</h3><img src="data:image/png;base64,{img_b64}" style="max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 8px;"/>'
    
    # Pares min e max
    pairs = [
        ("temp_min", "lux_min", "Temperatura mínima (°C)", "Luminosidade mínima (lux)", "Temp_min × Lux_min"),
        ("temp_max", "lux_max", "Temperatura máxima (°C)", "Luminosidade máxima (lux)", "Temp_max × Lux_max")
    ]
    
    for xcol, ycol, xlabel, ylabel, title in pairs:
        if xcol in df.columns and ycol in df.columns:
            x = df[xcol].to_numpy(dtype=float)
            y = df[ycol].to_numpy(dtype=float)
            img_b64 = scatter_with_regression_base64(x, y, xlabel, ylabel, title)
            if img_b64:
                plots_html += f'<h3>📈 {title}</h3><img src="data:image/png;base64,{img_b64}" style="max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 8px;"/>'
    
    if not plots_html:
        plots_html = "<p>❌ Não há pares de colunas adequadas para correlação (ex.: temp_avg & lux_avg).</p>"
    
    return f'''
    <div style="font-family: Inter, system-ui, Arial; padding: 20px; max-width: 800px; margin: auto;">
        <h2>🔗 Correlação: Temperatura × Luminosidade</h2>
        <p>Usuário: <strong>{session.get('username')}</strong> | <a href="/">Voltar</a> | <a href="/logout">Sair</a></p>
        {plots_html}
    </div>
    '''

# ========== INICIALIZAÇÃO ==========

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Dashboard PI com MFA Microsoft/Google Authenticator")
    print("=" * 60)
    print("📊 Acesse: http://localhost:8080")
    print("👤 Usuário demo: admin / admin123")
    print("📱 Configure com Microsoft Authenticator ou Google Authenticator")
    print("=" * 60)
    
    app.run(debug=True, host="0.0.0.0", port=8080)