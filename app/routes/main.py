# Importar componentes necessários do Flask
from flask import Blueprint, render_template
# Importar decorators e objetos do Flask-Login
from flask_login import login_required, current_user

# Criar Blueprint para rotas principais da aplicação
# Sem url_prefix, as rotas começam diretamente da raiz (/)
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
# @login_required  # Decorator que protege a rota - requer autenticação
def index():
    """
    Página inicial do sistema (protegida).
    
    Apenas usuários autenticados podem acessar esta página.
    Se não autenticado, será redirecionado para a página de login.
    
    Returns:
        Renderiza o template index.html com dados do usuário atual
    """
    # current_user é um objeto especial do Flask-Login que representa
    # o usuário atualmente autenticado na sessão
    return render_template('index.html')

@main_bp.route('/dashboard')
@login_required  # Esta rota também requer autenticação
def dashboard():
    """
    Página de dashboard (protegida).
    
    Exemplo de rota adicional protegida. Pode ser usada para
    exibir estatísticas, relatórios ou informações do usuário.
    
    Returns:
        Renderiza o template dashboard.html com dados do usuário
    """
    return render_template('dashboard.html', user=current_user)
