import asyncio
import uuid
from typing import Literal

from pydantic import BaseModel, Field

from agents import (
    Agent,
    Runner,
    SQLiteSession,
    function_tool,
)

from supportops_core_v3 import (
    IncidentState,
    IncidentReport,
    hybrid_router,
    hooks,
    incident_commander,
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

class WarRoomDecisionV2(WarRoomDecision):

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


warroom_commander_v2 = Agent[IncidentState](
    name="War Room Commander V2",

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

Produza WarRoomDecisionV2.
""",

    output_type=WarRoomDecisionV2,
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
# REMEDIATION EXECUTOR
# ============================================================

remediation_executor = Agent[IncidentState](
    name="Remediation Executor",

    instructions="""
Você executa SOMENTE ações aprováveis propostas pela War Room.

Você possui tools que representam alterações sensíveis.

REGRAS:

- Não execute ações apenas porque são possíveis.
- Use somente ações justificadas pela decisão final.
- Não reinicie servidor sem causa operacional suficiente.
- Não altere permissão M365 sem evidência de problema de permissão.
- Não revogue sessões ou resete MFA sem justificativa de segurança.
- Cada ação sensível exige aprovação humana.
- Se nenhuma ação for suficientemente justificada,
  não chame tools.

Explique ao final quais ações foram realizadas
e quais foram rejeitadas ou não necessárias.
""",

    tools=[
        revoke_user_sessions,
        reset_user_mfa,
        change_mailbox_permission,
        restart_server,
    ],

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


def approval_prompt(
    name,
    arguments,
):

    print("\n" + "!" * 78)
    print("HUMAN APPROVAL REQUIRED")
    print("!" * 78)

    print(f"\nTool: {name}")
    print(f"Argumentos: {arguments}")

    answer = input(
        "\nAPROVAR execução? [s/N]: "
    ).strip().lower()

    return answer in {
        "s",
        "sim",
        "y",
        "yes",
    }


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
                        "A ação foi rejeitada pelo "
                        "operador humano."
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

def print_v2_decision(
    decision: WarRoomDecisionV2,
):

    print("\n" + "=" * 80)
    print("SUPPORTOPS WAR ROOM V2 - COMMAND DECISION")
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
        "supportops-warroom-v2",
        "support_memory.db",
    )

    print("=" * 80)
    print("SUPPORTOPS WAR ROOM V2")
    print("Evidence + Timeline + Consensus + Human Approval")
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
            "WAR2-"
            + uuid.uuid4().hex[:8].upper()
        )

        state = IncidentState(
            incident_id=incident_id
        )

        initial_prompt = f"""
Incident ID: {incident_id}

INCIDENTE:

{user_input}
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
            warroom_commander_v2,
            final_prompt,
            state,
        )

        print_v2_decision(
            final_result
        )

        # ====================================================
        # FASE 7 - HUMAN CONTROL
        # ====================================================

        print("\n" + "=" * 80)
        print("FASE 7 - REMEDIATION / HUMAN APPROVAL")
        print("=" * 80)

        executor_prompt = f"""
INCIDENT ID:
{incident_id}

DECISÃO FINAL DA WAR ROOM:

{
    final_result.model_dump_json(
        indent=2
    )
}

Analise quais ações sensíveis,
se houver alguma,
devem ser propostas agora.

Não execute ações sem justificativa.
"""

        execution_result = await run_with_approvals(
            remediation_executor,
            executor_prompt,
            state,
        )

        print("\n" + "=" * 80)
        print("RESULTADO DA REMEDIAÇÃO")
        print("=" * 80)

        print(execution_result.final_output)

        # ====================================================
        # ORCHESTRATION MAP
        # ====================================================

        print("\n" + "=" * 80)
        print("AGENTES QUE PARTICIPARAM")
        print("=" * 80)

        for name in state.agents_started:
            print(f"  -> {name}")

        print("\n" + "=" * 80)
        print("WAR ROOM V2 ENCERRADA")
        print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())