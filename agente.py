import asyncio
from dataclasses import dataclass, field

from agents import (
    Agent,
    Runner,
    RunContextWrapper,
    SQLiteSession,
    ModelSettings,
    function_tool,
    trace,
)


# ============================================================
# ESTADO LOCAL DA APLICAÇÃO
# ============================================================

@dataclass
class SupportContext:
    operador: str
    ambiente: str
    evidencias: list[str] = field(default_factory=list)


# ============================================================
# TOOLS — INFRAESTRUTURA
# ============================================================

@function_tool
def consultar_status_servidor(
    ctx: RunContextWrapper[SupportContext],
    nome: str,
) -> str:
    """
    Consulta o status atual de um servidor.

    Args:
        nome: Nome do servidor que deve ser consultado.
    """

    print(f"\n[TOOL:INFRA] Consultando servidor {nome}...")

    servidores = {
        "SRV-EMAIL": "ONLINE",
        "SRV-ARQUIVOS": "ONLINE",
        "SRV-BACKUP": "OFFLINE",
    }

    resultado = servidores.get(
        nome.upper(),
        "SERVIDOR NÃO ENCONTRADO",
    )

    evidencia = f"Servidor {nome.upper()}: {resultado}"

    ctx.context.evidencias.append(evidencia)

    print(f"[TOOL:INFRA] {evidencia}")

    return evidencia


# ============================================================
# TOOLS — MICROSOFT 365
# ============================================================

@function_tool
def consultar_permissao_caixa(
    ctx: RunContextWrapper[SupportContext],
    usuario: str,
    caixa: str,
) -> str:
    """
    Consulta a permissão de um usuário em uma caixa compartilhada.

    Args:
        usuario: Nome do usuário.
        caixa: Nome da caixa compartilhada.
    """

    print(
        f"\n[TOOL:M365] Consultando {usuario} "
        f"na caixa {caixa}..."
    )

    permissoes = {
        "MARIA|JURIDICO": "SEM PERMISSÃO",
        "CLAUDIO|FINANCEIRO": "FULL ACCESS",
        "JOAO|RH": "READ ONLY",
    }

    chave = f"{usuario.upper()}|{caixa.upper()}"

    resultado = permissoes.get(
        chave,
        "PERMISSÃO NÃO ENCONTRADA",
    )

    evidencia = (
        f"Permissão de {usuario.upper()} "
        f"em {caixa.upper()}: {resultado}"
    )

    ctx.context.evidencias.append(evidencia)

    print(f"[TOOL:M365] {evidencia}")

    return evidencia


# ============================================================
# TOOLS — SEGURANÇA
# ============================================================

@function_tool
def consultar_alertas_mfa(
    ctx: RunContextWrapper[SupportContext],
    usuario: str,
) -> str:
    """
    Consulta alertas recentes de autenticação e MFA de um usuário.

    Args:
        usuario: Nome do usuário.
    """

    print(
        f"\n[TOOL:SECURITY] Consultando alertas MFA "
        f"de {usuario}..."
    )

    alertas = {
        "MARIA": (
            "5 solicitações de MFA não reconhecidas "
            "durante a madrugada"
        ),
        "JOAO": "Nenhum alerta recente",
        "CLAUDIO": "Nenhum alerta recente",
    }

    resultado = alertas.get(
        usuario.upper(),
        "USUÁRIO NÃO ENCONTRADO",
    )

    evidencia = (
        f"Alertas de autenticação para "
        f"{usuario.upper()}: {resultado}"
    )

    ctx.context.evidencias.append(evidencia)

    print(f"[TOOL:SECURITY] {evidencia}")

    return evidencia


# ============================================================
# AGENTE ESPECIALISTA — INFRA
# ============================================================

infra_agent = Agent[SupportContext](
    name="Especialista de Infraestrutura",

    instructions="""
Você é especialista em infraestrutura.

Analise somente questões relacionadas a:
- servidores;
- disponibilidade;
- backup;
- rede;
- infraestrutura.

Quando o usuário fornecer o nome de um servidor,
use obrigatoriamente consultar_status_servidor.

Nunca invente status de infraestrutura.

Entregue ao orquestrador:
1. evidência encontrada;
2. interpretação técnica;
3. próxima ação recomendada.

Seja objetivo.
""",

    model="gpt-5.6-luna",

    tools=[
        consultar_status_servidor,
    ],
)


# ============================================================
# AGENTE ESPECIALISTA — MICROSOFT 365
# ============================================================

m365_agent = Agent[SupportContext](
    name="Especialista Microsoft 365",

    instructions="""
Você é especialista em Microsoft 365.

Analise somente questões relacionadas a:
- Outlook;
- Exchange Online;
- caixas compartilhadas;
- permissões;
- Microsoft 365.

Quando houver usuário e caixa compartilhada,
use obrigatoriamente consultar_permissao_caixa.

Nunca invente permissões.

Entregue ao orquestrador:
1. evidência encontrada;
2. interpretação técnica;
3. próxima ação recomendada.

Seja objetivo.
""",

    model="gpt-5.6-luna",

    model_settings=ModelSettings(
        parallel_tool_calls=False
    ),

    tools=[
        consultar_permissao_caixa,
    ],
)

# ============================================================
# AGENTE ESPECIALISTA — SECURITY
# ============================================================

security_agent = Agent[SupportContext](
    name="Especialista de Segurança",

    instructions="""
Você é especialista em segurança de identidade.

Analise somente questões relacionadas a:
- MFA;
- autenticação;
- tentativas de login;
- acesso suspeito;
- identidade.

Quando houver suspeita envolvendo MFA,
use obrigatoriamente consultar_alertas_mfa.

Nunca invente eventos de segurança.

Entregue ao orquestrador:
1. evidência encontrada;
2. interpretação do risco;
3. próxima ação recomendada.

Não execute alterações privilegiadas.
Seja objetivo.
""",

    model="gpt-5.6-luna",

    tools=[
        consultar_alertas_mfa,
    ],
)


# ============================================================
# AGENTES COMO TOOLS
# ============================================================

infra_tool = infra_agent.as_tool(
    tool_name="consultar_especialista_infra",
    tool_description=(
        "Consulta um especialista em infraestrutura para "
        "problemas de servidores, rede, backup e disponibilidade."
    ),
)


m365_tool = m365_agent.as_tool(
    tool_name="consultar_especialista_m365",
    tool_description=(
        "Consulta um especialista Microsoft 365 para "
        "Outlook, Exchange, caixas compartilhadas e permissões."
    ),
)


security_tool = security_agent.as_tool(
    tool_name="consultar_especialista_security",
    tool_description=(
        "Consulta um especialista em segurança para "
        "MFA, autenticação, identidade e acessos suspeitos."
    ),
)


# ============================================================
# ORQUESTRADOR
# ============================================================

orchestrator = Agent[SupportContext](
    name="Support Orchestrator",

    instructions="""
Você é o gerente de uma equipe técnica de suporte.

Você é responsável pela conversa com o usuário e pela
resposta final.

Você possui três especialistas:

- consultar_especialista_infra
- consultar_especialista_m365
- consultar_especialista_security

Não tente substituir um especialista quando o problema
pertencer claramente ao domínio dele.

Quando um incidente envolver vários domínios,
consulte TODOS os especialistas necessários antes de
produzir a resposta final.

Exemplo:

Problema com caixa compartilhada + MFA suspeito:
consulte M365 e Security.

Problema com servidor + Microsoft 365:
consulte Infra e M365.

Problema envolvendo os três:
consulte os três especialistas.

Nunca invente resultados de ferramentas ou evidências.

Sua função é correlacionar as análises dos especialistas.

A resposta final deve conter:

Resumo
Evidências
Análise
Próxima ação

Se houver risco de segurança, deixe isso explícito.
""",

    model="gpt-5.6-luna",

    tools=[
        infra_tool,
        m365_tool,
        security_tool,
    ],
)


# ============================================================
# APLICAÇÃO
# ============================================================

async def main():

    session_id = "support-lab-001"

    # Memória persistente da conversa.
    session = SQLiteSession(
        session_id,
        "support_memory.db",
    )

    await session.clear_session()

    # Estado local da aplicação.
    context = SupportContext(
        operador="Claudio",
        ambiente="LAB",
    )

    print("\n========================================")
    print("       SUPPORT ORCHESTRATOR v1")
    print("========================================")
    print("Digite 'sair' para finalizar.")
    print("Memória: SQLite")
    print("Tracing: habilitado")
    print("Modelo: gpt-5.6-luna")
    print("========================================")

    while True:

        chamado = input("\nVocê: ").strip()

        if chamado.lower() in {
            "sair",
            "exit",
            "quit",
        }:
            print("\nEncerrando Support Orchestrator.")
            break

        if not chamado:
            continue

        # Evidências pertencem somente à execução atual.
        context.evidencias.clear()

        with trace(
            workflow_name="Support Orchestrator",
            group_id=session_id,
        ):

            result = await Runner.run(
                orchestrator,
                chamado,
                context=context,
                session=session,
            )

        print("\n========================================")
        print("RESPOSTA DO ORQUESTRADOR")
        print("========================================")

        print(result.final_output)

        print("\n========================================")
        print("EVIDÊNCIAS COLETADAS")
        print("========================================")

        if context.evidencias:
            for evidencia in context.evidencias:
                print(f"- {evidencia}")
        else:
            print("Nenhuma ferramenta local foi utilizada.")

        usage = result.context_wrapper.usage

        print("\n========================================")
        print("USO DA API")
        print("========================================")

        print(f"Requisições: {usage.requests}")
        print(f"Input tokens: {usage.input_tokens}")
        print(f"Output tokens: {usage.output_tokens}")
        print(f"Total tokens: {usage.total_tokens}")


if __name__ == "__main__":
    asyncio.run(main())