import asyncio

from agents import (
    Agent,
    Runner,
    RunContextWrapper,
    function_tool,
    handoff,
)


# ============================================================
# TOOLS
# ============================================================

@function_tool
def consultar_status_servidor(nome: str) -> str:
    """
    Consulta o status atual de um servidor.

    Args:
        nome: Nome do servidor.
    """

    print(f"\n[TOOL INFRA] Consultando servidor: {nome}")

    servidores = {
        "SRV-EMAIL": "ONLINE",
        "SRV-ARQUIVOS": "ONLINE",
        "SRV-BACKUP": "OFFLINE",
    }

    resultado = servidores.get(
        nome.upper(),
        "SERVIDOR NÃO ENCONTRADO"
    )

    print(f"[TOOL INFRA] Resultado: {resultado}")

    return resultado


@function_tool
def consultar_permissao_caixa(
    usuario: str,
    caixa: str
) -> str:
    """
    Consulta a permissão de um usuário em uma caixa compartilhada.

    Args:
        usuario: Nome do usuário.
        caixa: Nome da caixa compartilhada.
    """

    print(
        f"\n[TOOL M365] Consultando {usuario} "
        f"na caixa {caixa}"
    )

    permissoes = {
        "CLAUDIO|FINANCEIRO": "FULL ACCESS",
        "MARIA|JURIDICO": "SEM PERMISSÃO",
        "JOAO|RH": "READ ONLY",
    }

    chave = f"{usuario.upper()}|{caixa.upper()}"

    resultado = permissoes.get(
        chave,
        "PERMISSÃO NÃO ENCONTRADA"
    )

    print(f"[TOOL M365] Resultado: {resultado}")

    return resultado


# ============================================================
# AGENTES ESPECIALISTAS
# ============================================================

infra_agent = Agent(
    name="Especialista Infraestrutura",

    handoff_description=(
        "Especialista em servidores, infraestrutura, "
        "rede, backup e disponibilidade."
    ),

    instructions="""
    Você é um especialista de infraestrutura.

    Resolva problemas relacionados a:
    - servidores
    - disponibilidade
    - backup
    - infraestrutura
    - rede

    Quando precisar verificar o status de um servidor,
    use a ferramenta consultar_status_servidor.

    Não invente resultados de monitoramento.
    Use a ferramenta quando houver informação disponível nela.

    Responda de forma curta, técnica e clara.
    """,

    model="gpt-5.6",

    tools=[
        consultar_status_servidor
    ],
)


m365_agent = Agent(
    name="Especialista Microsoft 365",

    handoff_description=(
        "Especialista em Microsoft 365, Outlook, Exchange, "
        "caixas compartilhadas e permissões."
    ),

    instructions="""
    Você é um especialista Microsoft 365.

    Resolva problemas relacionados a:
    - Outlook
    - Exchange Online
    - caixas compartilhadas
    - permissões
    - Microsoft 365

    Quando precisar verificar a permissão de um usuário
    em uma caixa compartilhada, use a ferramenta
    consultar_permissao_caixa.

    Não invente permissões.

    Responda de forma curta, técnica e clara.
    """,

    model="gpt-5.6",

    tools=[
        consultar_permissao_caixa
    ],
)


# ============================================================
# CALLBACKS DOS HANDOFFS
# ============================================================

def transferindo_para_infra(
    ctx: RunContextWrapper[None]
):
    print(
        "\n[HANDOFF] Triagem → Especialista Infraestrutura"
    )


def transferindo_para_m365(
    ctx: RunContextWrapper[None]
):
    print(
        "\n[HANDOFF] Triagem → Especialista Microsoft 365"
    )


# ============================================================
# AGENTE ORQUESTRADOR / TRIAGEM
# ============================================================

triage_agent = Agent(
    name="Agente de Triagem",

    instructions="""
    Você é responsável exclusivamente pela triagem.

    Analise o problema recebido e escolha o especialista correto.

    Problemas de servidores, rede, backup ou infraestrutura:
    transfira para o Especialista Infraestrutura.

    Problemas de Outlook, Exchange, Microsoft 365,
    caixas compartilhadas ou permissões:
    transfira para o Especialista Microsoft 365.

    Não tente resolver problemas especializados sozinho.
    Faça o handoff para o agente adequado.
    """,

    model="gpt-5.6",

    handoffs=[
        handoff(
            agent=infra_agent,
            on_handoff=transferindo_para_infra,
        ),

        handoff(
            agent=m365_agent,
            on_handoff=transferindo_para_m365,
        ),
    ],
)


# ============================================================
# EXECUÇÃO
# ============================================================

async def main():

    chamado = """
    A Maria não consegue acessar a caixa compartilhada JURIDICO
    no Outlook. Está recebendo acesso negado.
    Verifique a permissão dela.
    """

    print("\n======================================")
    print(" NOVO CHAMADO")
    print("======================================")
    print(chamado)

    result = await Runner.run(
        triage_agent,
        chamado
    )

    print("\n======================================")
    print(" RESPOSTA FINAL")
    print("======================================")
    print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())