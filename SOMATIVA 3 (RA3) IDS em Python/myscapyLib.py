
# https://scapy.readthedocs.io/en/latest/
# https://scapy.readthedocs.io/en/latest/api/scapy.packet.html

# sudo apt-get install python3-scapy
# python -m pip install scapy

from datetime import datetime
from scapy.all import *

#-----------------------------------------------------------------------------------------------------
# Declaraçao de protocolos
TIPO = {'ip':scapy.all.IP, 'icmp':scapy.all.ICMP, 'tcp': scapy.all.TCP}

#------------------------------------------------------------------------------------------------------
# Salva ALERTA NO LOG
def alerta(msg):
    with open('alerta.txt','a') as log:
        now = datetime.now()
        log.write(now.strftime("%d/%m/%Y %H:%M:%S") + ' --> ' + msg+'\n')

#------------------------------------------------------------------------------------------------------
# 1) carrega ou captura pacotes
# -- count = número de pacotes para sniffar
# -- Use count > 0 para capturar pacotes da rede (SNIFF), mas precisa ser administrador
def carregaPacotes(arquivo, count=0):
    try:
        if count > 0:
            pacotes = sniff(count=count)
            wrpcap(arquivo, pacotes)
        else:
            pacotes = rdpcap(arquivo)
    except Exception as e:
        print('ERRO: ', e)
        pacotes = None 

    return pacotes

#------------------------------------------------------------------------------------------------------
# 2) Mostra captura
# -- por default, mostra apenas o sumário
# -- por default, usa begin=0 e count=100 
def mostraPacotes(pacotes, **kwargs):
    if pacotes is None or len(pacotes) == 0: 
        print('Este arquivo está vazio')
        return
    
    print('Pacotes no arquivo: ', len(pacotes))
    p0 = datetime.fromtimestamp(int(pacotes[0].time))
    pn = datetime.fromtimestamp(int(pacotes[-1].time))
    print(f'Captura de: {p0} ate {pn}')
    print(f'Duracao em segundos: {(pn-p0).total_seconds()}')

    ini = kwargs.get('begin',0)
    fim = ini + kwargs.get('count', 100)
    sumario = kwargs.get('summary', True)

    for p in pacotes[ini:fim]:
        if not sumario:
            print(p.show())               
            # print(ls(p))
        else:
            print(p.summary())

#------------------------------------------------------------------------------------------------------
# 3) Conta pacotes por origem
# -- para detectar flood, o ideal é contar pacotes que chegaram em um intervalo muito próximo
def contaIPOrigem(packets):
    pkts = [p for p in packets if IP in p]

    origens = {}
    for p in pkts:
        ip = str(p[IP].src)
        origens[ip] = (origens[ip] + 1) if ip in origens else 0 
            
    return origens

#------------------------------------------------------------------------------------------------------
# 4) Conta pacotes por destino
# -- para detectar flood, o ideal é contar pacotes que chegaram em um intervalo muito próximo
def contaIPDestino(packets):
    pkts = [p for p in packets if IP in p]

    destinos = {}
    for p in pkts:
        ip = str(p[IP].dst)
        destinos[ip] = (destinos[ip] + 1) if ip in destinos else 0 
            
    return destinos

#------------------------------------------------------------------------------------------------------
# 5) Filtra os pacotes por tipo: ARP, IP, UDP, TCP ou ICMP
# -- 
def filtraTipo(packets, tipo):
    fp = [pkt for pkt in packets if tipo in pkt]
    return fp

#------------------------------------------------------------------------------------------------------
# 6) Filtra pacotes TCP por FLAG
# -- flags são passados como string 'FSRPAU'
def filtraTCP(packets, flags):
    fp1 = [p for p in packets if TCP in p]
    fp2 = [p for p in fp1 if str(p[TCP].flags) == flags]
    return fp2


#-------------------------------------------------------------------------
# DEMONSTRACAO DAS FUNCOES DA BIBLIOTECA

if __name__ == '__main__':

    pacotes = carregaPacotes('desafio.pcap') 
    mostraPacotes(pacotes, count=10)
    #pacotes = filtraTCP(pacotes,'S')
    # mostraPacotes(filtraTCP(pacotes,'SA'), count=10)
    #origens = contaIPOrigem(pacotes)
    #for k,v in origens.items(): print(k,'=',v)
    #mostraPacotes(filtraTipo(pacotes, scapy.all.ICMP))


   






    