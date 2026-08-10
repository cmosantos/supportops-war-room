import asyncio
import uuid
from typing import Literal

from pydantic import BaseModel, Field

from agents import (
    Agent,
    Runner,
    SQLiteSession,
    RunHooks,
    RunContextWrapper,
    handoff,
)

from agente import (
    infra_agent,
    m365_agent,
    security_agent,
)


# ============================================================
# ESTADO DA APLICAÇÃO
# ============================================================

class IncidentState(BaseModel):
    incident_id: str
    route: str | None = None

    evidencias: list = Field(default_factory=list)

    agents_started: list[str] = Field(default_factory=list)
    handoffs: list[str] = Field(default_factory=list)
    tools_called: list[str] = Field(default_factory=list)

    security_involved: bool = False
    m365_involved: bool = False
    infra_involved: bool = False


# ============================================================
# SAÍDA ESTRUTURADA
# ============================================================

class Evidence(BaseModel):
    area: Literal["Microsoft 365", "Infraestrutura", "Segurança"]
    status: Literal[
        "confirmado",
        "parcial",
        "falha_na_consulta",
        "nao_consultado",
    ]

    findings: list[str]
    limitations: list[str] = Field(default_factory=list)


class ActionItem(BaseModel):
    order: int
    action: str
    owner: str
    reason: str


class IncidentReport(BaseModel):
    incident_id: str

    summary: str

    priority: Literal["P1", "P2", "P3", "P4"]

    confidence: Literal["baixa", "media", "alta"]

    evidence: list[Evidence]

    correlation: str

    security_risk: bool

    next_actions: list[ActionItem]

    escalation: list[str]


# ============================================================
# OBSERVABILIDADE / HOOKS
# ============================================================

class OpsHooks(RunHooks):

    async def on_agent_start(self, context, agent):
        state = context.context

        if agent.name not in state.agents_started:
            state.agents_started.append(agent.name)

        print(f"\n[FLOW] Agente iniciado -> {agent.name}")

    async def on_handoff(self, context, from_agent, to_agent):
        state = context.context

        movement = f"{from_agent.name} -> {to_agent.name}"

        state.handoffs.append(movement)
        state.route = to_agent.name

        print(f"[FLOW] HANDOFF -> {movement}")

    async def on_tool_start(self, context, agent, tool):
        state = context.context

        tool_name = getattr(tool, "name", str(tool))

        state.tools_called.append(tool_name)

        lower = tool_name.lower()

        if "m365" in lower or "microsoft" in lower:
            state.m365_involved = True

        if "infra" in lower:
            state.infra_involved = True

        if "security" in lower or "segur" in lower:
            state.security_involved = True

        print(
            f"[FLOW] TOOL -> {agent.name} chamou {tool_name}"
        )

    async def on_tool_end(self, context, agent, tool, result):
        tool_name = getattr(tool, "name", str(tool))

        print(
            f"[FLOW] TOOL concluída -> {tool_name}"
        )


hooks = OpsHooks()


# ============================================================
# ESPECIALISTAS COMO TOOLS
# ============================================================

m365_pro_tool = m365_agent.as_tool(
    tool_name="consult_m365",
    tool_description=(
        "Investiga Microsoft 365, Outlook, Exchange, Teams, "
        "caixas compartilhadas e permissões."
    ),
    hooks=hooks,
)


infra_pro_tool = infra_agent.as_tool(
    tool_name="consult_infra",
    tool_description=(
        "Investiga servidores, CPU, memória, disco, rede, "
        "storage e problemas de infraestrutura."
    ),
    hooks=hooks,
)


security_pro_tool = security_agent.as_tool(
    tool_name="consult_security",
    tool_description=(
        "Investiga MFA, autenticação, identidade, sessões, "
        "credenciais e possíveis incidentes de segurança."
    ),
    hooks=hooks,
)


# ============================================================
# INCIDENT COMMANDER
# ============================================================

incident_commander = Agent[IncidentState](
    name="Incident Commander",

    instructions="""
Você é o Incident Commander de uma operação corporativa de TI.

Investigue incidentes complexos consultando todos os especialistas
necessários.

Você possui especialistas de:

- Microsoft 365
- Infraestrutura
- Segurança

REGRAS DE INVESTIGAÇÃO

1. Consulte todas as áreas explicitamente envolvidas.

2. Nunca invente resultados de ferramentas.

3. Diferencie:
   - evidência confirmada;
   - evidência parcial;
   - falha de consulta;
   - hipótese.

4. Não trate falha de consulta como evidência de normalidade.

5. Correlacione os resultados dos especialistas.

6. Segurança deve ter precedência quando existir risco real de
comprometimento de identidade.

REGRAS DE PRIORIDADE

P1:
Somente quando houver evidência de:
- comprometimento confirmado;
- indisponibilidade crítica;
- ataque ativo;
- impacto crítico generalizado.

P2:
Use para:
- possível comprometimento ainda não confirmado;
- impacto operacional importante;
- incidente que exige investigação rápida.

P3:
Use para:
- impacto limitado;
- falha individual sem risco significativo.

P4:
Use para:
- solicitação informativa;
- problema sem impacto operacional relevante.

Uma simples solicitação de MFA desconhecida, sem evidência adicional
de comprometimento, NÃO deve virar P1 automaticamente.

Gere obrigatoriamente um IncidentReport estruturado.

O incident_id deve ser exatamente o ID informado no contexto da
solicitação.
""",

    tools=[
        m365_pro_tool,
        infra_pro_tool,
        security_pro_tool,
    ],

    output_type=IncidentReport,

    model=security_agent.model,
)


# ============================================================
# ROUTER
# ============================================================

hybrid_router = Agent[IncidentState](
    name="Support Router",

    instructions="""
Você é responsável somente pela triagem.

Faça handoff direto quando existir UMA única área:

Microsoft 365:
Outlook, Exchange, Teams, permissões ou caixas compartilhadas.

Infraestrutura:
servidores, CPU, memória, disco, rede, storage ou lentidão.

Segurança:
MFA, autenticação, credenciais, login suspeito ou identidade.

Se houver DUAS OU MAIS áreas:

-> transfira para Incident Commander.

Se houver problema operacional junto com possível incidente
de segurança:

-> transfira para Incident Commander.

Não investigue incidentes complexos sozinho.
""",

    handoffs=[
        handoff(
            m365_agent,
            tool_name_override="transfer_to_m365",
        ),

        handoff(
            infra_agent,
            tool_name_override="transfer_to_infra",
        ),

        handoff(
            security_agent,
            tool_name_override="transfer_to_security",
        ),

        handoff(
            incident_commander,
            tool_name_override="transfer_to_incident_commander",
        ),
    ],

    model=security_agent.model,
)


# ============================================================
# APRESENTAÇÃO DO RELATÓRIO
# ============================================================

def print_report(report: IncidentReport):

    print("\n" + "=" * 72)
    print("SUPPORTOPS - INCIDENT REPORT")
    print("=" * 72)

    print(f"\nIncident ID : {report.incident_id}")
    print(f"Prioridade  : {report.priority}")
    print(f"Confiança   : {report.confidence}")
    print(f"Risco Sec.  : {report.security_risk}")

    print("\nRESUMO")
    print(report.summary)

    print("\nEVIDÊNCIAS")

    for evidence in report.evidence:
        print(
            f"\n[{evidence.area}] "
            f"Status: {evidence.status}"
        )

        for finding in evidence.findings:
            print(f"  + {finding}")

        for limitation in evidence.limitations:
            print(f"  ! Limitação: {limitation}")

    print("\nCORRELAÇÃO")
    print(report.correlation)

    print("\nPRÓXIMAS AÇÕES")

    for action in sorted(
        report.next_actions,
        key=lambda item: item.order,
    ):
        print(
            f"{action.order}. {action.action}"
            f"\n   Owner: {action.owner}"
            f"\n   Motivo: {action.reason}"
        )

    print("\nESCALONAMENTO")

    for escalation in report.escalation:
        print(f"- {escalation}")


# ============================================================
# EXECUÇÃO
# ============================================================

async def main():

    session = SQLiteSession(
        "supportops-pro-session",
        "support_memory.db",
    )

    print("=" * 72)
    print("SUPPORTOPS PRO - MULTI-AGENT INCIDENT COMMAND")
    print("=" * 72)

    print(
        "Router + Handoffs + Incident Commander + "
        "Structured Output + State + Hooks"
    )

    print("\nDigite 'sair' para encerrar.\n")

    while True:

        user_input = input("Você: ").strip()

        if user_input.lower() in {
            "sair",
            "exit",
            "quit",
        }:
            break

        if not user_input:
            continue

        incident_id = (
            "INC-"
            + uuid.uuid4().hex[:8].upper()
        )

        state = IncidentState(
            incident_id=incident_id
        )

        enriched_input = f"""
Incident ID: {incident_id}

Incidente reportado:

{user_input}
"""

        result = await Runner.run(
            hybrid_router,
            enriched_input,
            context=state,
            session=session,
            hooks=hooks,
        )

        # ----------------------------------------------------
        # RESULTADO
        # ----------------------------------------------------

        if isinstance(
            result.final_output,
            IncidentReport,
        ):
            print_report(result.final_output)

        else:
            print("\nRESPOSTA")
            print(result.final_output)

        # ----------------------------------------------------
        # ESTADO INTERNO
        # ----------------------------------------------------

        print("\n" + "=" * 72)
        print("ESTADO DA EXECUÇÃO")
        print("=" * 72)

        print(f"Incident ID: {state.incident_id}")
        print(f"Rota final : {state.route}")

        print("\nAgentes executados:")
        for agent_name in state.agents_started:
            print(f"  -> {agent_name}")

        print("\nHandoffs:")
        if state.handoffs:
            for movement in state.handoffs:
                print(f"  -> {movement}")
        else:
            print("  Nenhum")

        print("\nTools executadas:")
        for tool_name in state.tools_called:
            print(f"  -> {tool_name}")

        # ----------------------------------------------------
        # USAGE
        # ----------------------------------------------------

        usage = result.context_wrapper.usage

        print("\n" + "=" * 72)
        print("TELEMETRIA")
        print("=" * 72)

        print(
            f"Requests     : {usage.requests}"
        )

        print(
            f"Input tokens : {usage.input_tokens}"
        )

        print(
            f"Output tokens: {usage.output_tokens}"
        )

        print(
            f"Total tokens : {usage.total_tokens}"
        )

        print(
            f"Agente final : {result.last_agent.name}"
        )

        print("=" * 72)


if __name__ == "__main__":
    asyncio.run(main())