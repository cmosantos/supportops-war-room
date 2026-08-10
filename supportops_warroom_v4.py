import asyncio
import json
import re
import uuid
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from agents import (
    Agent,
    Runner,
    SQLiteSession,
    function_tool,
    ModelSettings,
    trace,
)

from supportops_core_v3 import (
    IncidentState,
    IncidentReport,
    hybrid_router,
    hooks,
    incident_commander,
    m365_agent,
)

from supportops_warroom import (
    WarRoomAnalysis,
    AdversarialReview,
    WarRoomDecision,
    correlation_agent,
    identity_agent,
    forensics_agent,
    impact_agent,
    recovery_agent,
    change_agent,
    communications_agent,
    skeptic_agent,
)


# ============================================================
# M365 STRUCTURED INPUT GUARD
# ============================================================

class M365InvestigationInput(BaseModel):
    usuario: str = Field(
        description=(
            "Nome ou UPN da pessoa real investigada. "
            "Exemplo: Carlos ou carlos@empresa.com. "
            "NUNCA use Incident ID, WAR4-..., INC-... ou texto de controle."
        )
    )
    mailbox: str = Field(
        description=(
            "Nome da caixa compartilhada real. "
            "Exemplo: FINANCEIRO. Nunca use Incident ID."
        )
    )
    incident_summary: str = Field(
        description="Resumo curto apenas dos fatos M365 relevantes."
    )

    @field_validator("usuario")
    @classmethod
    def validate_usuario(cls, value: str) -> str:
        clean = value.strip()

        if not clean:
            raise ValueError("usuario não pode ser vazio")

        if "incident id" in clean.lower():
            raise ValueError(
                "usuario deve ser uma pessoa/UPN, nunca o Incident ID"
            )

        if re.search(
            r"\b(?:WAR|INC)\d*-[A-Z0-9]+\b",
            clean,
            flags=re.IGNORECASE,
        ):
            raise ValueError(
                "usuario contém um identificador de incidente; "
                "extraia a pessoa real do relato"
            )

        return clean

    @field_validator("mailbox")
    @classmethod
    def validate_mailbox(cls, value: str) -> str:
        clean = value.strip()

        if not clean:
            raise ValueError("mailbox não pode ser vazia")

        if "incident id" in clean.lower() or re.search(
            r"\b(?:WAR|INC)\d*-[A-Z0-9]+\b",
            clean,
            flags=re.IGNORECASE,
        ):
            raise ValueError(
                "mailbox deve ser a caixa real, nunca o Incident ID"
            )

        return clean


if isinstance(m365_agent.instructions, str):
    m365_agent.instructions += """

REGRA CRÍTICA DE IDENTIFICADORES:
- O campo usuario representa SEMPRE uma pessoa real ou UPN.
- Valores como Incident ID, WAR4-..., WAR2-..., INC-... são metadados e
  NUNCA podem ser enviados como usuario para tools M365.
- O campo mailbox representa SEMPRE a caixa real, por exemplo FINANCEIRO.
- Ao receber input estruturado, use exatamente os campos usuario e mailbox.
- Se um identificador de incidente aparecer perto do nome da pessoa, ignore
  o identificador e preserve a identidade humana.
"""


m365_structured_tool = m365_agent.as_tool(
    tool_name="investigate_m365",
    tool_description=(
        "Investiga Microsoft 365 usando identidade humana e mailbox "
        "explicitamente separadas. Nunca aceita Incident ID como usuário."
    ),
    parameters=M365InvestigationInput,
    include_input_schema=True,
    hooks=hooks,
)


incident_commander.tools = [
    (
        m365_structured_tool
        if getattr(tool, "name", None) == "investigate_m365"
        else tool
    )
    for tool in incident_commander.tools
]


# ============================================================
# TIMELINE
# ============================================================

class TimelineEvent(BaseModel):
    order: int
    timestamp: str | None = None
    event: str
    source: str
    status: Literal[
        "confirmado",
        "relatado",
        "inferido",
        "desconhecido",
    ]


class TimelineReport(BaseModel):
    incident_id: str
    events: list[TimelineEvent]
    temporal_correlations: list[str]
    temporal_gaps: list[str]
    warnings: list[str]


timeline_agent = Agent[IncidentState](
    name="Incident Timeline Analyst",

    instructions="""
Você é especialista em reconstrução de timeline de incidentes.

Sua função é organizar os eventos conhecidos em ordem temporal.

Classifique cada evento como:

- confirmado;
- relatado;
- inferido;
- desconhecido.

Nunca invente horário.

Proximidade temporal NÃO significa causalidade.

Identifique:
- lacunas de horário;
- eventos que precisam de timestamp exato;
- possíveis relações temporais;
- contradições na sequência.

Produza TimelineReport.
""",

    output_type=TimelineReport,
    model=incident_commander.model,
)


# ============================================================
# EVIDENCE QUALITY
# ============================================================

class EvidenceQualityReport(BaseModel):
    incident_id: str

    evidence_score: int = Field(
        ge=0,
        le=100,
    )

    strong_evidence: list[str]
    weak_evidence: list[str]
    missing_evidence: list[str]

    unsupported_claims: list[str]

    collection_priorities: list[str]

    confidence: Literal[
        "baixa",
        "media",
        "alta",
    ]


evidence_quality_agent = Agent[IncidentState](
    name="Evidence Quality Analyst",

    instructions="""
Você avalia a QUALIDADE das evidências do incidente.

Não investigue novamente.

Avalie o material produzido pelos outros agentes.

Pontue de 0 a 100 considerando:

- logs disponíveis;
- evidência técnica;
- confirmação independente;
- timestamps;
- rastreabilidade;
- lacunas;
- hipóteses ainda não verificadas.

Uma afirmação do usuário é evidência de relato,
não necessariamente evidência técnica.

Uma tool que retorna "não encontrado"
não significa automaticamente inexistência.

Produza EvidenceQualityReport.
""",

    output_type=EvidenceQualityReport,
    model=incident_commander.model,
)


# ============================================================
# CONSENSUS ENGINE
# ============================================================

class ConsensusReport(BaseModel):
    incident_id: str

    consensus_score: int = Field(
        ge=0,
        le=100,
    )

    recommended_priority: Literal[
        "P1",
        "P2",
        "P3",
        "P4",
    ]

    security_risk_score: int = Field(
        ge=0,
        le=100,
    )

    agreed_findings: list[str]

    disagreements: list[str]

    minority_opinions: list[str]

    unresolved_questions: list[str]

    reasoning: str


consensus_agent = Agent[IncidentState](
    name="Consensus Judge",

    instructions="""
Você é responsável por medir consenso entre os analistas.

Você NÃO deve decidir pela maioria cegamente.

Compare:

- Correlation Analyst
- Identity Threat Analyst
- Digital Forensics Analyst
- Business Impact Analyst
- Recovery Planner
- Change Risk Analyst
- Incident Communications
- Timeline Analyst
- Evidence Quality Analyst
- Skeptic Red Team

Determine:

- onde existe consenso;
- onde existem divergências;
- opiniões minoritárias importantes;
- perguntas ainda sem resposta.

Calcule:

consensus_score:
0 = conflito completo
100 = forte convergência

security_risk_score:
0 = risco mínimo
100 = comprometimento/ataque crítico fortemente suportado

Prioridade deve considerar evidências e impacto,
não apenas número de agentes concordando.

Produza ConsensusReport.
""",

    output_type=ConsensusReport,
    model=incident_commander.model,
)


# ============================================================
# WAR ROOM COMMANDER V2
# ============================================================

class WarRoomDecisionV4(WarRoomDecision):

    consensus_score: int = Field(
        ge=0,
        le=100,
    )

    evidence_score: int = Field(
        ge=0,
        le=100,
    )

    security_risk_score: int = Field(
        ge=0,
        le=100,
    )

    timeline_summary: str

    decision_rationale: str


warroom_commander_v4 = Agent[IncidentState](
    name="War Room Commander V4",

    instructions="""
Você é a autoridade final da War Room.

Você receberá:

1. investigação operacional;
2. análises dos especialistas;
3. timeline;
4. avaliação da qualidade das evidências;
5. revisão adversarial;
6. consenso entre os agentes.

Sua função é ARBITRAR.

Não faça média simples.

Priorize:

EVIDÊNCIA
>
IMPACTO
>
CONSENSO
>
OPINIÃO

Uma maioria de agentes pode estar errada.

Se Evidence Quality indicar evidência fraca,
reduza confiança mesmo que o consenso seja alto.

Se Red Team apresentar objeção válida,
resolva a objeção explicitamente.

P1 exige suporte objetivo.

Produza WarRoomDecisionV4.
""",

    output_type=WarRoomDecisionV4,
    model=incident_commander.model,
)

# ============================================================
# REMEDIATION PLAN V4
# ============================================================

class RemediationAction(BaseModel):
    action_id: str

    action_type: Literal[
        "revoke_sessions",
        "reset_mfa",
        "change_mailbox_permission",
        "restart_server",
    ]

    target: str

    mailbox: str | None = None
    permission: str | None = None

    reason: str

    evidence_basis: list[str]

    risk_if_executed: str

    eligible_now: bool


class RemediationPlan(BaseModel):
    incident_id: str

    mode: Literal[
        "read_only",
        "approval_required",
        "no_action",
    ]

    actions: list[RemediationAction]

    blocked_actions: list[str]

    notes: list[str]


remediation_planner = Agent[IncidentState](
    name="Remediation Planner V4",

    instructions="""
Você converte a decisão final da War Room em um plano
ESTRUTURADO de execução.

Você não executa nada.

As únicas ações permitidas são:

revoke_sessions
reset_mfa
change_mailbox_permission
restart_server

REGRAS:

Uma ação só pode ter eligible_now=true quando houver
evidência técnica suficiente na decisão final.

Revogação de sessões:
permitida quando houver evidência significativa de sessão,
token ou autenticação suspeita.

Reset de MFA:
permitido quando houver forte indício de comprometimento
de identidade ou abuso de MFA.

Alteração de permissão:
somente quando a própria permissão estiver comprovadamente
incorreta.

Restart de servidor:
somente quando houver justificativa operacional clara e
quando preservação de evidências já tiver sido considerada.

Não transforme recomendação investigativa em ação executável.

Se não houver ação adequada agora, use read_only ou no_action.

Cada ação deve citar em evidence_basis os fatos concretos
que justificam a execução.

Produza RemediationPlan.
""",

    output_type=RemediationPlan,

    model=incident_commander.model,
)

# ============================================================
# AÇÕES SENSÍVEIS - SIMULADAS
# ============================================================

@function_tool(needs_approval=True)
async def revoke_user_sessions(
    username: str,
    reason: str,
) -> str:

    print(
        f"\n[ACTION] Revogando sessões de {username}..."
    )

    return (
        f"SIMULAÇÃO: sessões de {username} "
        f"revogadas. Motivo: {reason}"
    )


@function_tool(needs_approval=True)
async def reset_user_mfa(
    username: str,
    reason: str,
) -> str:

    print(
        f"\n[ACTION] Resetando MFA de {username}..."
    )

    return (
        f"SIMULAÇÃO: MFA de {username} resetado. "
        f"Motivo: {reason}"
    )


@function_tool(needs_approval=True)
async def change_mailbox_permission(
    username: str,
    mailbox: str,
    permission: str,
    reason: str,
) -> str:

    print(
        f"\n[ACTION] Alterando permissão "
        f"{permission} de {username} em {mailbox}..."
    )

    return (
        f"SIMULAÇÃO: permissão {permission} "
        f"alterada para {username} em {mailbox}. "
        f"Motivo: {reason}"
    )


@function_tool(needs_approval=True)
async def restart_server(
    server: str,
    reason: str,
) -> str:

    print(
        f"\n[ACTION] Reiniciando servidor {server}..."
    )

    return (
        f"SIMULAÇÃO: servidor {server} reiniciado. "
        f"Motivo: {reason}"
    )


# ============================================================
# DETERMINISTIC POLICY ENGINE
# ============================================================

class PolicyDecision(BaseModel):
    action_id: str
    allowed: bool
    reason: str


def evaluate_policy(
    action: RemediationAction,
    decision: WarRoomDecisionV4,
) -> PolicyDecision:

    if not action.eligible_now:
        return PolicyDecision(
            action_id=action.action_id,
            allowed=False,
            reason=(
                "O Remediation Planner marcou a ação "
                "como não elegível neste momento."
            ),
        )

    if action.action_type in {"revoke_sessions", "reset_mfa"}:
        if decision.security_risk_score < 70:
            return PolicyDecision(
                action_id=action.action_id,
                allowed=False,
                reason="Security Risk abaixo do limiar operacional de 70.",
            )

        if decision.evidence_score < 60:
            return PolicyDecision(
                action_id=action.action_id,
                allowed=False,
                reason="Evidence Score insuficiente para contenção de identidade.",
            )

    if action.action_type == "change_mailbox_permission":
        if not action.mailbox:
            return PolicyDecision(
                action_id=action.action_id,
                allowed=False,
                reason="Mailbox não informada.",
            )

        if not action.permission:
            return PolicyDecision(
                action_id=action.action_id,
                allowed=False,
                reason="Permissão não informada.",
            )

        if decision.evidence_score < 70:
            return PolicyDecision(
                action_id=action.action_id,
                allowed=False,
                reason="Evidência insuficiente para alteração administrativa.",
            )

    if action.action_type == "restart_server":
        if decision.evidence_score < 75:
            return PolicyDecision(
                action_id=action.action_id,
                allowed=False,
                reason="Evidência insuficiente para reinício de servidor.",
            )

        if decision.priority not in {"P1", "P2"}:
            return PolicyDecision(
                action_id=action.action_id,
                allowed=False,
                reason="Prioridade não justifica ação disruptiva.",
            )

    return PolicyDecision(
        action_id=action.action_id,
        allowed=True,
        reason="A ação passou pelas políticas determinísticas da War Room.",
    )


# ============================================================
# EXECUTION ADAPTER V4
# ============================================================

def build_execution_agent(action: RemediationAction):

    tool_map = {
        "revoke_sessions": revoke_user_sessions,
        "reset_mfa": reset_user_mfa,
        "change_mailbox_permission": change_mailbox_permission,
        "restart_server": restart_server,
    }

    selected_tool = tool_map[action.action_type]

    return Agent[IncidentState](
        name=f"Execution Adapter - {action.action_type}",
        instructions="""
Você é um adaptador de execução.

Existe somente UMA tool disponível.
Você DEVE chamar essa tool exatamente uma vez.
Use exatamente os argumentos fornecidos no payload.

Não faça nova investigação.
Não produza recomendações.
Não substitua a execução por texto.
""",
        tools=[selected_tool],
        model=incident_commander.model,
        model_settings=ModelSettings(tool_choice="required"),
        tool_use_behavior="stop_on_first_tool",
    )


def build_execution_payload(action: RemediationAction) -> dict:
    if action.action_type == "revoke_sessions":
        return {"username": action.target, "reason": action.reason}

    if action.action_type == "reset_mfa":
        return {"username": action.target, "reason": action.reason}

    if action.action_type == "change_mailbox_permission":
        return {
            "username": action.target,
            "mailbox": action.mailbox,
            "permission": action.permission,
            "reason": action.reason,
        }

    if action.action_type == "restart_server":
        return {"server": action.target, "reason": action.reason}

    raise ValueError(f"Ação desconhecida: {action.action_type}")


# ============================================================
# POST-ACTION VALIDATION
# ============================================================

class ValidationReport(BaseModel):
    incident_id: str
    status: Literal["validated", "partial", "no_actions"]
    executed_actions: list[str]
    rejected_actions: list[str]
    blocked_actions: list[str]
    residual_risk: str
    recommended_next_step: str


post_action_validator = Agent[IncidentState](
    name="Post-Action Validator",
    instructions="""
Você valida o resultado da fase de remediação.

Diferencie:
- ações executadas;
- ações bloqueadas por policy;
- ações rejeitadas pelo humano;
- ações que não foram necessárias.

Não trate uma ação simulada como prova de que o incidente inteiro foi resolvido.
Avalie o risco residual e determine o próximo passo.

Produza ValidationReport.
""",
    output_type=ValidationReport,
    model=incident_commander.model,
)


# ============================================================
# HELPERS
# ============================================================

async def run_analysis(
    agent,
    prompt,
    state,
):

    result = await Runner.run(
        agent,
        prompt,
        context=state,
        hooks=hooks,
    )

    return result.final_output


def approval_prompt(name, arguments):

    print("\n")
    print("!" * 80)
    print("!" * 80)
    print("               🚨  APROVAÇÃO HUMANA OBRIGATÓRIA  🚨")
    print("!" * 80)
    print("!" * 80)

    print(f"\nAÇÃO SOLICITADA:")
    print(f"  {name}")

    print(f"\nARGUMENTOS:")
    print(f"  {arguments}")

    print("\n" + "=" * 80)
    print("DECISÃO DO OPERADOR")
    print("=" * 80)

    print("\n  [ S ]  APROVAR A EXECUÇÃO")
    print("  [ N ]  REJEITAR A EXECUÇÃO")

    while True:

        answer = input(
            "\n>>> DIGITE S PARA APROVAR OU N PARA REJEITAR: "
        ).strip().lower()

        if answer in {"s", "sim", "y", "yes"}:
            return True

        if answer in {"n", "nao", "não", "no"}:
            return False

        print(
            "\n⚠️  OPÇÃO INVÁLIDA — DIGITE S OU N."
        )

async def run_with_approvals(
    agent,
    prompt,
    state,
):
    result = await Runner.run(
        agent,
        prompt,
        context=state,
        hooks=hooks,
    )

    while result.interruptions:

        run_state = result.to_state()

        for interruption in result.interruptions:

            approved = approval_prompt(
                interruption.name or "unknown_tool",
                interruption.arguments,
            )

            if approved:

                print("\n[APPROVAL] APROVADO")

                run_state.approve(
                    interruption,
                    always_approve=False,
                )

            else:

                print("\n[APPROVAL] REJEITADO")

                run_state.reject(
                    interruption,
                    rejection_message=(
                        "A ação foi rejeitada pelo operador humano."
                    ),
                )

        result = await Runner.run(
            agent,
            run_state,
            hooks=hooks,
        )
    return result

# ============================================================
# DISPLAY
# ============================================================

def print_v4_decision(
    decision: WarRoomDecisionV4,
):

    print("\n" + "=" * 80)
    print("SUPPORTOPS WAR ROOM V4 - COMMAND DECISION")
    print("=" * 80)

    print(
        f"\nIncident ID       : {decision.incident_id}"
    )

    print(
        f"Prioridade        : {decision.priority}"
    )

    print(
        f"Confiança         : {decision.confidence}"
    )

    print(
        f"Consensus Score   : "
        f"{decision.consensus_score}/100"
    )

    print(
        f"Evidence Score    : "
        f"{decision.evidence_score}/100"
    )

    print(
        f"Security Risk     : "
        f"{decision.security_risk_score}/100"
    )

    print("\nRESUMO")
    print(decision.executive_summary)

    print("\nTIMELINE")
    print(decision.timeline_summary)

    print("\nJUSTIFICATIVA DA DECISÃO")
    print(decision.decision_rationale)

    print("\nFATOS")
    for item in decision.confirmed_facts:
        print(f"  + {item}")

    print("\nHIPÓTESES")
    for item in decision.open_hypotheses:
        print(f"  ? {item}")

    print("\nCONTENÇÃO")
    for item in decision.security_containment:
        print(f"  -> {item}")

    print("\nINVESTIGAÇÃO")
    for index, item in enumerate(
        decision.investigation_plan,
        start=1,
    ):
        print(f"  {index}. {item}")

    print("\nRECUPERAÇÃO")
    for item in decision.recovery_plan:
        print(f"  -> {item}")

    print("\nNÃO FAZER")
    for item in decision.changes_to_avoid:
        print(f"  X {item}")


# ============================================================
# MAIN
# ============================================================

async def main():

    session = SQLiteSession(
        "supportops-warroom-v4",
        "support_memory.db",
    )

    print("=" * 80)
    print("SUPPORTOPS WAR ROOM V4 + LANGSMITH TRACE V5.2")
    print("Evidence + Timeline + Consensus + Policy Engine + Human Approval")
    print("=" * 80)

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
            "WAR4-"
            + uuid.uuid4().hex[:8].upper()
        )

        state = IncidentState(
            incident_id=incident_id
        )

        with trace(
            "SupportOps War Room Incident",
            group_id=incident_id,
            metadata={
                "incident_id": incident_id,
                "system": "SupportOps",
                "workflow": "War Room",
                "observability_version": "V5.2",
            },
        ):
            initial_prompt = f"""
    METADADOS DE CONTROLE:
    Incident ID: {incident_id}

    IMPORTANTE:
    O Incident ID acima é somente metadado interno.
    Ele NUNCA representa usuário, UPN, mailbox, servidor ou ativo.

    RELATO ORIGINAL DO INCIDENTE:

    {user_input}

    REGRA DE EXTRAÇÃO:
    Ao chamar tools, use somente entidades reais extraídas do relato original.
    Exemplo: se o relato mencionar Carlos e FINANCEIRO, use usuario=Carlos
    e mailbox=FINANCEIRO. Nunca use {incident_id} como argumento operacional.
    """

            # ====================================================
            # FASE 1
            # ====================================================

            print("\n" + "=" * 80)
            print("FASE 1 - TRIAGEM / CORE INVESTIGATION")
            print("=" * 80)

            core_result = await Runner.run(
                hybrid_router,
                initial_prompt,
                context=state,
                session=session,
                hooks=hooks,
            )

            if not isinstance(
                core_result.final_output,
                IncidentReport,
            ):

                print("\nCASO SIMPLES")
                print(core_result.final_output)
                continue

            core_report = core_result.final_output

            report_text = (
                core_report.model_dump_json(
                    indent=2
                )
            )

            # ====================================================
            # FASE 2
            # ====================================================

            print("\n" + "=" * 80)
            print("FASE 2 - SPECIALIST SWARM")
            print("=" * 80)

            specialist_agents = [
                correlation_agent,
                identity_agent,
                forensics_agent,
                impact_agent,
                recovery_agent,
                change_agent,
                communications_agent,
            ]

            analyses = await asyncio.gather(
                *[
                    run_analysis(
                        agent,
                        report_text,
                        state,
                    )
                    for agent in specialist_agents
                ]
            )

            analyses_text = "\n\n".join(
                analysis.model_dump_json(
                    indent=2
                )
                for analysis in analyses
            )

            # ====================================================
            # FASE 3 - TIMELINE + QUALITY
            # ====================================================

            print("\n" + "=" * 80)
            print("FASE 3 - TIMELINE + EVIDENCE QUALITY")
            print("=" * 80)

            meta_prompt = f"""
    INCIDENT ID:
    {incident_id}

    RELATÓRIO OPERACIONAL:

    {report_text}

    ANÁLISES ESPECIALIZADAS:

    {analyses_text}
    """

            timeline_result, quality_result = (
                await asyncio.gather(
                    run_analysis(
                        timeline_agent,
                        meta_prompt,
                        state,
                    ),
                    run_analysis(
                        evidence_quality_agent,
                        meta_prompt,
                        state,
                    ),
                )
            )

            timeline_text = (
                timeline_result.model_dump_json(
                    indent=2
                )
            )

            quality_text = (
                quality_result.model_dump_json(
                    indent=2
                )
            )

            # ====================================================
            # FASE 4 - RED TEAM
            # ====================================================

            print("\n" + "=" * 80)
            print("FASE 4 - ADVERSARIAL RED TEAM")
            print("=" * 80)

            red_prompt = f"""
    INCIDENT ID:
    {incident_id}

    RELATÓRIO:

    {report_text}

    ANÁLISES:

    {analyses_text}

    TIMELINE:

    {timeline_text}

    QUALIDADE DAS EVIDÊNCIAS:

    {quality_text}

    Faça revisão adversarial.
    """

            red_result = await run_analysis(
                skeptic_agent,
                red_prompt,
                state,
            )

            red_text = (
                red_result.model_dump_json(
                    indent=2
                )
            )

            # ====================================================
            # FASE 5 - CONSENSUS
            # ====================================================

            print("\n" + "=" * 80)
            print("FASE 5 - CONSENSUS ENGINE")
            print("=" * 80)

            consensus_prompt = f"""
    INCIDENT ID:
    {incident_id}

    RELATÓRIO:

    {report_text}

    ANÁLISES:

    {analyses_text}

    TIMELINE:

    {timeline_text}

    QUALIDADE DAS EVIDÊNCIAS:

    {quality_text}

    RED TEAM:

    {red_text}

    Meça o consenso.
    """

            consensus_result = await run_analysis(
                consensus_agent,
                consensus_prompt,
                state,
            )

            consensus_text = (
                consensus_result.model_dump_json(
                    indent=2
                )
            )

            # ====================================================
            # FASE 6 - FINAL COMMAND
            # ====================================================

            print("\n" + "=" * 80)
            print("FASE 6 - WAR ROOM COMMAND")
            print("=" * 80)

            final_prompt = f"""
    INCIDENT ID:
    {incident_id}

    RELATÓRIO:

    {report_text}

    ANÁLISES:

    {analyses_text}

    TIMELINE:

    {timeline_text}

    QUALIDADE:

    {quality_text}

    RED TEAM:

    {red_text}

    CONSENSO:

    {consensus_text}

    Produza decisão final.
    """

            final_result = await run_analysis(
                warroom_commander_v4,
                final_prompt,
                state,
            )

            print_v4_decision(
                final_result
            )

            # ====================================================
            # FASE 7 - REMEDIATION PLANNING
            # ====================================================

            print("\n" + "=" * 80)
            print("FASE 7 - STRUCTURED REMEDIATION PLAN")
            print("=" * 80)

            remediation_prompt = f"""
    INCIDENT ID:
    {incident_id}

    DECISÃO FINAL:

    {
        final_result.model_dump_json(
            indent=2
        )
    }

    Transforme a decisão em um RemediationPlan.
    """

            plan_result = await Runner.run(
                remediation_planner,
                remediation_prompt,
                context=state,
                hooks=hooks,
            )

            remediation_plan = plan_result.final_output

            print(f"\nModo: {remediation_plan.mode}")
            print(f"Ações propostas: {len(remediation_plan.actions)}")

            # ====================================================
            # FASE 8 - POLICY ENGINE
            # ====================================================

            print("\n" + "=" * 80)
            print("FASE 8 - DETERMINISTIC POLICY ENGINE")
            print("=" * 80)

            allowed_actions = []
            blocked_actions = []

            for action in remediation_plan.actions:
                policy = evaluate_policy(action, final_result)

                print(f"\n[{action.action_id}] {action.action_type}")
                print(f"Target: {action.target}")
                print(f"Policy: {'ALLOW' if policy.allowed else 'BLOCK'}")
                print(f"Reason: {policy.reason}")

                if policy.allowed:
                    allowed_actions.append(action)
                else:
                    blocked_actions.append(
                        f"{action.action_id}: {action.action_type} - {policy.reason}"
                    )

            for item in remediation_plan.blocked_actions:
                blocked_actions.append(item)

            # ====================================================
            # FASE 9 - CONTROLLED EXECUTION
            # ====================================================

            print("\n" + "=" * 80)
            print("FASE 9 - CONTROLLED EXECUTION")
            print("=" * 80)

            execution_log = []
            rejected_log = []

            for action in allowed_actions:
                print("\n" + "-" * 80)
                print(f"AÇÃO ELEGÍVEL: {action.action_type}")
                print(f"Target: {action.target}")
                print(f"Motivo: {action.reason}")
                print("Evidências:")

                for evidence in action.evidence_basis:
                    print(f"  + {evidence}")

                print(f"Risco da ação: {action.risk_if_executed}")

                payload = build_execution_payload(action)
                executor = build_execution_agent(action)

                executor_prompt = f"""
    ACTION ID:
    {action.action_id}

    ACTION TYPE:
    {action.action_type}

    PAYLOAD:

    {
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        )
    }

    Chame a única tool disponível exatamente uma vez
    usando exatamente esse payload.
    """

                execution_result = await run_with_approvals(
                    executor,
                    executor_prompt,
                    state,
                )

                output = str(execution_result.final_output)
                if "rejeitad" in output.lower():
                    rejected_log.append(f"{action.action_id}: {action.action_type} - {output}")
                else:
                    execution_log.append(f"{action.action_id}: {output}")

            # ====================================================
            # FASE 10 - POST ACTION VALIDATION
            # ====================================================

            print("\n" + "=" * 80)
            print("FASE 10 - POST-ACTION VALIDATION")
            print("=" * 80)

            validation_prompt = f"""
    INCIDENT ID:
    {incident_id}

    DECISÃO:
    {
        final_result.model_dump_json(
            indent=2
        )
    }

    REMEDIATION PLAN:
    {
        remediation_plan.model_dump_json(
            indent=2
        )
    }

    EXECUTION LOG:
    {
        json.dumps(
            execution_log,
            ensure_ascii=False,
            indent=2,
        )
    }

    REJECTED ACTIONS:
    {
        json.dumps(
            rejected_log,
            ensure_ascii=False,
            indent=2,
        )
    }

    BLOCKED ACTIONS:
    {
        json.dumps(
            blocked_actions,
            ensure_ascii=False,
            indent=2,
        )
    }

    Valide o estado após a fase de execução.
    """

            validation_result = await Runner.run(
                post_action_validator,
                validation_prompt,
                context=state,
                hooks=hooks,
            )

            validation = validation_result.final_output

            print(f"\nValidation Status : {validation.status}")
            print(f"Residual Risk     : {validation.residual_risk}")
            print(f"Next Step         : {validation.recommended_next_step}")

            print("\nAções executadas:")
            if execution_log:
                for item in execution_log:
                    print(f"  -> {item}")
            else:
                print("  Nenhuma")

            print("\nAções rejeitadas:")
            if rejected_log:
                for item in rejected_log:
                    print(f"  -> {item}")
            else:
                print("  Nenhuma")

            print("\nAções bloqueadas:")
            if blocked_actions:
                for item in blocked_actions:
                    print(f"  -> {item}")
            else:
                print("  Nenhuma")

            # ====================================================
            # ORCHESTRATION MAP
            # ====================================================

            print("\n" + "=" * 80)
            print("AGENTES QUE PARTICIPARAM")
            print("=" * 80)

            for name in state.agents_started:
                print(f"  -> {name}")

            print("\n" + "=" * 80)
            print("WAR ROOM V4 ENCERRADA")
            print("=" * 80)

if __name__ == "__main__":
    asyncio.run(main())