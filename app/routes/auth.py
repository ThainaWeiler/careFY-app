# Importar componentes necessários do Flask
from flask import Blueprint, render_template, redirect, url_for, request, flash
# Importar funções de autenticação do Flask-Login
from flask_login import login_user, logout_user, login_required
# Importar o modelo de usuário e a instância do banco de dados
from app.models.user import User
from app.models.especialista import Especialista
from app import db

# Criar um Blueprint para rotas de autenticação
# Blueprint permite organizar rotas relacionadas em módulos separados
# url_prefix='/auth' significa que todas as rotas terão /auth/ no início
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Rota de login do sistema.
    
    GET: Exibe o formulário de login
    POST: Processa as credenciais e autentica o usuário
    
    Returns:
        GET: Renderiza template login.html
        POST: Redireciona para página inicial ou exibe erro
    """
    # Verificar se é uma requisição POST (envio do formulário)
    if request.method == 'POST':
        # Obter dados do formulário
        username = request.form.get('username')
        password = request.form.get('password')
        # Checkbox "Lembrar-me" (retorna False se não marcado)
        remember = request.form.get('remember', False)
        
        # Validar se os campos foram preenchidos
        if not username or not password:
            flash('Por favor, preencha todos os campos.', 'warning')
            return render_template('login.html')
        
        # Buscar usuário no banco de dados pelo nome de usuário
        # .first() retorna o primeiro resultado ou None
        user = User.query.filter_by(username=username).first()
        
        # Verificar se usuário existe e senha está correta
        if user and user.check_password(password):
            # Verificar se a conta está ativa
            if user.is_active:
                # Fazer login do usuário (cria sessão)
                # remember=True mantém o login mesmo após fechar o navegador
                login_user(user, remember=remember)
                flash(f'Bem-vindo, {user.username}!', 'success')
                
                # Redirecionar para a página que o usuário tentou acessar antes do login
                # Se não houver página anterior, vai para a página inicial
                next_page = request.args.get('next')
                return redirect(next_page or url_for('main.index'))
            else:
                flash('Sua conta está desativada.', 'danger')
        else:
            flash('Usuário ou senha incorretos.', 'danger')
    
    # Se for GET ou houver erro, exibir o formulário de login
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required  # Decorator que garante que apenas usuários autenticados podem acessar
def logout():
    """
    Rota de logout do sistema.
    Encerra a sessão do usuário e redireciona para o login.
    
    Returns:
        Redireciona para a página de login
    """
    # Encerrar a sessão do usuário
    logout_user()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Rota de registro de novos usuários.
    Esta rota é opcional - pode ser removida se você quiser que apenas
    administradores criem usuários via console Python.
    
    GET: Exibe formulário de cadastro
    POST: Processa e cria novo usuário
    
    Returns:
        GET: Renderiza template register.html
        POST: Redireciona para login ou exibe erro
    """
    if request.method == 'POST':
        # Obter dados do formulário
        username = request.form.get('nome_completo')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validar se todos os campos foram preenchidos
        if not all([username, email, password, confirm_password]):
            flash('Por favor, preencha todos os campos.', 'warning')
            return render_template('register.html')
        
        # Verificar se as senhas coincidem
        if password != confirm_password:
            flash('As senhas não coincidem.', 'danger')
            return render_template('register.html')
        
        if request.form.get('role') == "paciente":
            # Verificar se o nome de usuário já existe
            if User.query.filter_by(username=username).first():
                flash('Este nome de usuário já está em uso.', 'danger')
                return render_template('register.html')
            
            # Verificar se o email já está cadastrado
            if User.query.filter_by(email=email).first():
                flash('Este email já está cadastrado.', 'danger')
                return render_template('register.html')
            
            # Criar novo objeto User
            new_user = User(username=username, email=email)
            # Definir senha (será criptografada automaticamente)
            new_user.set_password(password)
            
            # Tentar salvar no banco de dados
            try:
                # Adicionar usuário à sessão do banco
                db.session.add(new_user)
                # Confirmar a transação (salvar no banco)
                db.session.commit()
                flash('Conta criada com sucesso! Faça login.', 'success')
                return redirect(url_for('auth.login'))
            except Exception as e:
                # Se houver erro, desfazer a transação
                db.session.rollback()
                flash('Erro ao criar conta. Tente novamente.', 'danger')
        
        if request.form.get('role') == "especialista":
                    # Verificar se o nome de usuário já existe
            if Especialista.query.filter_by(username=username).first():
                flash('Este nome de usuário já está em uso.', 'danger')
                return render_template('register.html')
            
            # Verificar se o email já está cadastrado
            if Especialista.query.filter_by(email=email).first():
                flash('Este email já está cadastrado.', 'danger')
                return render_template('register.html')
            
            # Criar novo objeto User
            new_especialista = Especialista(username=username, email=email)
            # Definir senha (será criptografada automaticamente)
            new_especialista.set_password(password)
            
            # Tentar salvar no banco de dados
            try:
                # Adicionar usuário à sessão do banco
                db.session.add(new_especialista)
                # Confirmar a transação (salvar no banco)
                db.session.commit()
                flash('Conta criada com sucesso! Faça login.', 'success')
                return redirect(url_for('auth.login'))
            except Exception as e:
                # Se houver erro, desfazer a transação
                db.session.rollback()
                flash('Erro ao criar conta. Tente novamente.', 'danger')
        
    # Se for GET ou houver erro, exibir o formulário de registro
    return render_template('register.html')
