# Importar as extensões necessárias do pacote app
from app import db, login_manager
# UserMixin: Classe helper que adiciona métodos necessários para Flask-Login
from flask_login import UserMixin
# Funções para hash e verificação de senhas
from werkzeug.security import generate_password_hash, check_password_hash
# Para timestamps automáticos
from datetime import datetime

class User(UserMixin, db.Model):
    """
    Modelo de usuário para autenticação e gerenciamento de contas.
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    cpf = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        """Criptografa e armazena a senha do usuário."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verifica se a senha fornecida corresponde ao hash armazenado."""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    """Carrega um usuário pelo ID armazenado na sessão."""
    return User.query.get(int(user_id))


# Função auxiliar para login via CPF
def authenticate_by_cpf(cpf, password):
    """
    Autentica um usuário utilizando CPF e senha.
    
    Args:
        cpf (str): CPF fornecido pelo usuário
        password (str): Senha em texto plano
    
    Returns:
        User: Objeto do usuário autenticado ou None se falhar
    """
    user = User.query.filter_by(cpf=cpf).first()
    if user and user.check_password(password):
        return user
    return None