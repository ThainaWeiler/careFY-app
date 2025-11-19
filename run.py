# Importar a factory function que cria a aplicação
from app import create_app

# Criar a instância da aplicação
app = create_app()

# Verificar se o script está sendo executado diretamente (não importado)
if __name__ == '__main__':
    # Executar o servidor de desenvolvimento Flask
    # debug=True: Ativa o modo de depuração (reinicialização automática e mensagens de erro detalhadas)
    # host='0.0.0.0': Permite acesso de outros dispositivos na rede local
    # port=5000: Define a porta do servidor (padrão Flask)
    app.run(debug=True, host='0.0.0.0', port=55555)

