# Importar as extensões necessárias do pacote app
from app import db, login_manager
# UserMixin: Classe helper que adiciona métodos necessários para Flask-Login
from flask_login import UserMixin
# Funções para hash e verificação de senhas
from werkzeug.security import generate_password_hash, check_password_hash
# Para timestamps automáticos
from datetime import datetime
from .user import User

class Especialista(UserMixin, db.Model):
    """
    Modelo de usuário para autenticação e gerenciamento de contas.
    
    Herda de:
        UserMixin: Fornece implementações padrão para métodos do Flask-Login
        db.Model: Classe base do SQLAlchemy para modelos de banco de dados
    
    Atributos:
        id: Chave primária do usuário
        username: Nome de usuário único
        email: Endereço de email único
        password_hash: Senha criptografada (nunca armazenamos senhas em texto plano)
        created_at: Data e hora de criação da conta
        is_active: Status da conta (ativa/inativa)
    """
    # Nome da tabela no banco de dados
    __tablename__ = 'especialista'
    
    # Definição das colunas da tabela
    # id: Chave primária com auto-incremento
    id = db.Column(db.Integer, primary_key=True)
    
    # username: String única de até 80 caracteres, não pode ser nulo
    # index=True cria um índice para buscas mais rápidas
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    
    # email: String única de até 120 caracteres, não pode ser nulo
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    
    # password_hash: Armazena a senha criptografada (nunca a senha original)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # created_at: Timestamp automático da criação do usuário
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # is_active: Indica se a conta está ativa (permite desativar sem deletar)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        """
        Criptografa e armazena a senha do usuário.
        
        Args:
            password: Senha em texto plano fornecida pelo usuário
        
        A função generate_password_hash cria um hash seguro usando
        o algoritmo pbkdf2:sha256 por padrão.
        """
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """
        Verifica se a senha fornecida corresponde ao hash armazenado.
        
        Args:
            password: Senha em texto plano para verificar
        
        Returns:
            bool: True se a senha está correta, False caso contrário
        """
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        """
        Representação em string do objeto User (útil para debugging).
        
        Returns:
            str: Representação legível do usuário
        """
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    """
    Função callback necessária para o Flask-Login.
    Carrega um usuário pelo ID armazenado na sessão.
    
    Args:
        user_id: ID do usuário (string) armazenado na sessão
    
    Returns:
        User: Objeto do usuário ou None se não encontrado
    
    Esta função é chamada automaticamente pelo Flask-Login
    em cada requisição para carregar o usuário atual.
    """
    return Especialista.query.get(int(user_id))
