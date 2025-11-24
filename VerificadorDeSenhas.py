import re 
import sys

# Importação para mascarar a entrada da senha 
try:
    from stdiomask import getpass as masked_getpass
except ImportError:
    from getpass import getpass as masked_getpass

import requests # Para fazer a chamada na API
import hashlib  # Para criar o hash SHA-1 da senha

def verificar_forca_senha(senha):
    """
    Analisa a força de uma senha com base em múltiplos critérios
    e retorna um nível de força e sugestões.
    """
    pontuacao = 0
    sugestoes = []

    # --- 1. Verificação de Comprimento ---

    if len(senha) < 8:
        sugestoes.append("A senha deve ter pelo menos 8 caracteres.")
        pontuacao -= 5 
    elif len(senha) < 12:
        pontuacao += 1
        sugestoes.append("Considere usar uma senha com 12 ou mais caracteres.")
    else:
        pontuacao += 3 

    # --- 2. Verificação de Tipos de Caracteres ---
    # Usa Regex para encontrar padrões.
    
    # Verifica se há letras minúsculas (a-z)
    if re.search(r'[a-z]', senha):
        pontuacao += 1
    else:
        sugestoes.append("Inclua pelo menos uma letra minúscula (a-z).")

    # Verifica se há letras maiúsculas (A-Z)
    if re.search(r'[A-Z]', senha):
        pontuacao += 1
    else:
        sugestoes.append("Inclua pelo menos uma letra maiúscula (A-Z).")

    # Verifica se há números (0-9)
    if re.search(r'[0-9]', senha):
        pontuacao += 1
    else:
        sugestoes.append("Inclua pelo menos um número (0-9).")

    # Verifica se há caracteres especiais
    # \W em Regex significa "qualquer caractere que NÃO é letra ou número"
    if re.search(r'[\W_]', senha):
        pontuacao += 2 # Caracteres especiais dão um bônus maior
    else:
        sugestoes.append("Inclua pelo menos um caractere especial (ex: !@#$).")

    # --- 3. Cálculo do Resultado Final ---
    # Define o nível com base na pontuação total.
    if pontuacao < 2:
        nivel = "Muito Fraca"
    elif pontuacao < 4:
        nivel = "Fraca"
    elif pontuacao < 6:
        nivel = "Média"
    else:
        nivel = "Forte"

    return nivel, sugestoes

# --- Verificação de Vazamentos  ---
def verificar_vazamento_pwned(senha):
    """
    Verifica se a senha aparece em vazamentos de dados usando a API do HIBP.
    A API usa um método k-Anonymity, então a senha real nunca é enviada.
    """
    try:
        # 1. Cria um hash SHA-1 da senha (é o padrão exigido pela API)
        sha1_senha = hashlib.sha1(senha.encode('utf-8')).hexdigest().upper()
        prefixo_hash = sha1_senha[:5] # Pega os 5 primeiros caracteres do hash
        sufixo_hash = sha1_senha[5:]  # Pega o restante do hash
        
        # 2. Faz a requisição para a API
        url = f"https://api.pwnedpasswords.com/range/{prefixo_hash}"
        resposta = requests.get(url)

        if resposta.status_code != 200:
            print(f"\n[AVISO] Erro ao verificar vazamentos (API retornou {resposta.status_code}).")
            return False, 0 

        # 3. Verifica a lista de hashes retornados
        # A API retorna uma lista de sufixos de hash que começam com o mesmo prefixo
        hashes_vazados = (linha.split(':') for linha in resposta.text.splitlines())
        
        for hash_vazado, contagem in hashes_vazados:
            if hash_vazado == sufixo_hash:
                # Encontrou! A senha está em um vazamento.
                return True, int(contagem)

    except requests.RequestException as e:
        print(f"\n[AVISO] Erro de conexão ao verificar vazamentos: {e}")
        return False, 0 

    # 4. Se saiu do loop, a senha não foi encontrada
    return False, 0

def main():
    """
    Função principal para executar o verificador.
    """
    print("Verificador de Força de Senha")
    print("Digite uma senha para análise (ou 'sair' para fechar).")

    while True:
        try:
            senha_usuario = masked_getpass(prompt="Digite a senha: ", mask='*')
        except Exception as e:
            print(f"\nErro ao tentar mascarar senha ({e}), usando input padrão.")
            senha_usuario = input("Digite a senha: ")


        if senha_usuario.lower() == 'sair':
            print("Até logo!")
            break
        
        if not senha_usuario:
            print("Nenhuma senha digitada. Tente novamente.")
            continue

        # --- Parte Principal ---
        nivel, sugestoes = verificar_forca_senha(senha_usuario)

        print(f"\nResultado da Análise:")
        print(f"[ Força da Senha: {nivel} ]")

        if sugestoes:
            print("\nSugestões para melhorar:")
            for sugestao in sugestoes:
                print(f"- {sugestao}")       
        print("\nVerificando em vazamentos de dados...")
        vazou, contagem = verificar_vazamento_pwned(senha_usuario)
        if vazou:
            print(f"!!! ALERTA !!! Esta senha é INSEGURA.")
            print(f"Ela já apareceu {contagem:,} vezes em vazamentos de dados conhecidos.")
            print("Por favor, escolha outra senha.")
        else:
            print("INFO: Senha não encontrada em vazamentos públicos conhecidos.")
        
        print("\n" + "-"*30 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nVerificação interrompida. Até logo!")
        sys.exit(0)