import myscapyLib as IDS

#-------------------------------------------------------------------------
# REGRA 1: DETECTAR ICMP FLOOD UMA FONTE (PING OF DEATH)
# -- uma fonte está enviando pacotes com uma taxa muito alta
def detectaPoD(pacotes, limite):
    # A) filtre pacotes do tipo ICMP  
    icmp_packages = IDS.filtraTipo(pacotes, IDS.TIPO['icmp'])

    # B) crie o dicionário com o número de pacotes por origem
    origens = IDS.contaIPOrigem(icmp_packages)

    # C) selecione os IPs cujo número de pacotes enviados excede o valor limite
    resultado = []
    for k, v in origens.items():
        if v > limite:
            resultado.append(k)

    # D) gere uma mensagem de alerta para cada IP na seleção indicado que estão fazendo o ataque    
    for ip in resultado:
        IDS.alerta(f'O IP {ip} esta fazendo ICMP Flood')
    if len(resultado) == 0:
        print('PoD não foi detectado ou eu não fiz o exercicio')

#-------------------------------------------------------------------------    
# REGRA 2: DETECTAR ICMP FLOOD DE VARIAS FONTES (Distributed PING OF DEATH)
# -- um alvo está recebendo ICMP com uma taxa muito alta
def detectaDPoD(pacotes, limite):
    # A) filtre pacotes do tipo ICMP
    icmp_packages = IDS.filtraTipo(pacotes, IDS.TIPO['icmp'])

    # B) crie o dicionário com o número de pacotes por destino
    destinos = IDS.contaIPDestino(icmp_packages)

    # C) selecione os IPs cujo número de pacotes recebidos excede o valor limite
    resultado = []
    for k, v in destinos.items():
        if v > limite:
            resultado.append(k)

    # D) gere uma mensagem de alerta para indicando quem está sendo atacado    
    for ip in resultado:
        IDS.alerta(f'O IP {ip} esta sendo ATACADO por ICMP Flood (DISTRIBUIDO)')
    if len(resultado) == 0:
        print('DPoD não foi detectado ou eu não fiz o exercicio')

#-------------------------------------------------------------------------
# REGRA 3: DETECTAR SYN FLOOD PELA ORIGEM OU DESTINO
# -- uma fonte está enviando pacotes SYN com uma taxa muito alta
# -- uma destino está rebendo pacotes SYN com uma taxa muito alta
def detectaSYNFlood(pacotes, limite):
    # A) filtre pacotes pelo flag S do TCP
    syn_packages = IDS.filtraTCP(pacotes, 'S')

    # B) crie um dicionário com o número de pacotes por origem
    origens = IDS.contaIPOrigem(syn_packages)

    # C) selecione os IPs cujo número de pacotes enviados excede o valor limite
    resultado = []
    for k, v in origens.items():
        if v > limite:
            resultado.append(k)

    # D) gere uma mensagem de alerta para cada IP na seleção indicado que estão fazendo o ataque    
    for ip in resultado:
        IDS.alerta(f'O IP {ip} esta fazendo SYN Flood')
    
    # E) crie o dicionário com o número de pacotes por destino
    destinos = IDS.contaIPDestino(syn_packages)

    # F) selecione os IPs cujo número de pacotes recebidos excede o valor limite
    resultado = []
    for k, v in destinos.items():
        if v > limite:
            resultado.append(k)

    # G) gere uma mensagem de alerta para indicando quem está sendo atacado 
    for ip in resultado:
        IDS.alerta(f'O IP {ip} esta sendo atacado SYN Flood')
    if len(resultado) == 0:
        print('SYN FLOOD não foi detectado ou eu não fiz o exercicio')

#-------------------------------------------------------------------------
# REGRA 4: DETECTAR PORT SCAN 
# -- uma fonte está enviando pacotes para diversas portas
def detectaPSCAN(pacotes, limite):
    # A) filtre pacotes pelo flag S do TCP
    syn_packages = IDS.filtraTCP(pacotes, 'S')

    # B) crie um dicionário com a chave IP de origem e valor do conjunto de portas de destino
    origens = {}
    for syn_package in syn_packages:
        ip = str(syn_package[IDS.TIPO['ip']].src)
        port = int(syn_package[IDS.TIPO['tcp']].dport)
        if not ip in origens:
            origens[ip] = set()
        origens[ip].add(port)

    # C) selecione os IPs cujo número de portas endereçadas excede o valor limite
    resultado = []
    for k, v in origens.items():
        if len(v) > limite:
            resultado.append(k)

    # D) gere uma mensagem de alerta para cada IP na seleção indicado que estão fazendo o ataque 
    for ip in resultado:
        IDS.alerta(f'O IP {ip} esta fazendo PORT SCAN')
    if len(resultado) == 0:
        print('PORT SCAN não foi detectado ou eu não fiz o exercicio')
        
#-------------------------------------------------------------------------
# REGRA 5: DETECTAR ATAQUE SYN ACK -- SMURF
# -- estão chegando pacotes SA de origens para nunca foi enviando S
def detectaSYNACK(pacotes, limite):
    # A) lista_SA = filtre pacotes pelo flag SA do TCP e crie um conjunto com os IPs de destino
    listaSA = set(IDS.contaIPDestino(IDS.filtraTCP(pacotes, 'SA')).keys())

    # B) lista_S = filtre pacotes pelos flags S do TCP e crie um conjunto com os IPs de origem
    listaS = set(IDS.contaIPOrigem(IDS.filtraTCP(pacotes, 'S')).keys())

    # C) Calcule o complemento da lista_SA e lista_A (lista_SA - lista_A)
    resultado = listaSA - listaS

    # D) gere uma mensagem de alerta para cada IP na seleção indicado que estão fazendo o ataque 
    for ip in resultado:
        IDS.alerta(f'O IP {ip} esta sendo atacado por SYN ACK')
    if len(resultado) == 0:
        print('SYN ACK não foi detectado ou eu não fiz o exercício')

#-------------------------------------------------------------------------
if __name__ == '__main__':

    pacotes = IDS.carregaPacotes('desafio.pcap') 
    #IDS.mostraPacotes(pacotes, count=10)

    detectaPoD(pacotes, limite=100)
    detectaDPoD(pacotes, limite=100)
    detectaSYNFlood(pacotes, limite=100)
    detectaPSCAN(pacotes, limite=50)
    detectaSYNACK(pacotes, limite=100)
