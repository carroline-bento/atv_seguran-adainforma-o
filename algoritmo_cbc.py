""" Implementação do algoritmo CBC com IV- Trabalho N1 - Segurança da Informação
    Feito por: Ana Caroline Bento Santos        Matrícula: 20211103010065"""

""" Passos para fazer a implementação do CBC:
1 - Divisão da mensagem ✅
2 - Geração do IV ✅
3 - Operação XOR do 1° bloco com o IV ✅
4 - Operação XOR com o bloco anterior ✅
5 - Decifração ✅

"""

import os

# definindo o tamanho do bloco (em bytes) e a chave de cifra simétrica
tamanho_do_bloco = 16
minha_chave = b"chave-carroline-b" # o 'b' na frente da string significa que ele vai considerar ela como um objeto bytes literal

# função de cifragem
def encriptar(mensagem):
    # gerando um vetor de inicialização aleatório
    vetor_inicializacao = os.urandom(tamanho_do_bloco)
    
    # adicionando o vetor de inicialização na frente da mensagem original
    mensagem_tamanho_definido = vetor_inicializacao + mensagem
    
    # preenchendo a mensagem para ter um número inteiro de blocos
    mensagem_tamanho_definido += b"\0" * (tamanho_do_bloco - len(mensagem_tamanho_definido) % tamanho_do_bloco)
    
    # dividindo a mensagem em blocos e cifra um a um
    blocos_cifrados_original = []
    bloco_anterior = vetor_inicializacao
    for i in range(0, len(mensagem_tamanho_definido), tamanho_do_bloco):
        bloco = mensagem_tamanho_definido[i:i+tamanho_do_bloco]
        resultado_xor = bytes([bloco[j] ^ bloco_anterior[j] for j in range(tamanho_do_bloco)])
        bloco_cifrado = b""
        for j in range(tamanho_do_bloco):
            texto_cifrado_byte = (resultado_xor[j] + minha_chave[j]) % 256
            bloco_cifrado += bytes([texto_cifrado_byte])
        blocos_cifrados_original.append(bloco_cifrado)
        bloco_anterior = bloco_cifrado
    
    # Retorna a mensagem cifrada como uma concatenação dos blocos cifrados
    return b"".join(blocos_cifrados_original)

# Define a função de decifração
def decriptar(texto_cifrado):
    # Extrai o vetor de inicialização da mensagem cifrada
    vetor_inicializacao = texto_cifrado[:tamanho_do_bloco]
    
    # Divide a mensagem cifrada em blocos e decifra um a um
    blocos_descriptografados = []
    bloco_anterior = vetor_inicializacao
    for i in range(tamanho_do_bloco, len(texto_cifrado), tamanho_do_bloco):
        bloco = texto_cifrado[i:i+tamanho_do_bloco]
        resultado_xor = b""
        for j in range(tamanho_do_bloco):
            resultado_xor_byte = (bloco[j] - minha_chave[j]) % 256
            resultado_xor += bytes([resultado_xor_byte])
        bloco_descriptografado = bytes([resultado_xor[j] ^ bloco_anterior[j] for j in range(tamanho_do_bloco)])
        blocos_descriptografados.append(bloco_descriptografado)
        bloco_anterior = bloco
    
    # Remove o preenchimento da mensagem original e retorna como string
    return b"".join(blocos_descriptografados).rstrip(b"\0").decode("utf-8")

# Recebe a mensagem do usuário e cifra
mensagem = input("Digite a mensagem a ser cifrada: ").encode("utf-8")
texto_cifrado = encriptar(mensagem)

print(f'Mensagem encriptada: {texto_cifrado}')

# Decifra a mensagem e exibe na tela
texto_decriptado = decriptar(texto_cifrado)
print("Mensagem decifrada:", texto_decriptado)