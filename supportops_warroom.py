import asyncio
import uuid
from typing import Literal

from pydantic import BaseModel, Field

from agents import Agent, Runner, SQLiteSession

from supportops_pro import (
    IncidentState,
    IncidentReport,
    hybrid_router,
    hooks,
    incident_commander,
)


# ============================================================
# MODELOS DA WAR ROOM
# ============================================================

class WarRoomAnalysis(BaseModel):
    role: str

    confidence: Literal[
        "baixa",
        "media",
        "alta",
    ]

    verdict: str

    findings: list[str] = Field(default_factory=list)

    risks: list[str] = Field(default_factory=list)

    missing_evidence: list[str] = Field(default_factory=list)

    recommendations: list[str] = Field(default_factory=list)


class AdversarialReview(BaseModel):
    accepted_findings: list[str]

    challenged_findings: list[str]

    unsupported_claims: list[str]

    contradictions: list[str]

    missing_evidence: list[str]

    priority_assessment: str

    confidence: Literal[
        "baixa",
        "media",
        "alta",
    ]


class WarRoomDecision(BaseModel):
    incident_id: str

    executive_summary: str

    priority: Literal[
        "P1",
        "P2",
        "P3",
        "P4",
    ]

    confidence: Literal[
        "baixa",
        "media",
        "alta",
    ]

    confirmed_facts: list[str]

    open_hypotheses: list[str]

    contradictions: list[str]

    security_containment: list[str]

    evidence_preservation: list[str]

    investigation_plan: list[str]

    recovery_plan: list[str]

    changes_to_avoid: list[str]

    escalation: list[str]

    p1_triggers: list[str]

    split_incident_criteria: list[str]

    executive_message: str


# ============================================================
# 1 - CORRELATION ANALYST
# ============================================================

correlation_agent = Agent[IncidentState](
    name="Correlation Analyst",

    instructions="""
Você é especialista em correlação de incidentes.

Analise o relatório técnico inicial e determine se eventos de áreas
diferentes possuem relação temporal, causal ou apenas coincidência.

Nunca transforme proximidade temporal em causalidade automaticamente.

Procure:

- relações entre identidade, Microsoft 365 e infraestrutura;
- sequência temporal;
- sintomas que podem ter causa comum;
- sintomas provavelmente independentes;
- contradições;
- lacunas de evidência.

Desafie correlações fracas.

Produza WarRoomAnalysis.
""",

    output_type=WarRoomAnalysis,
    model=incident_commander.model,
)


# ============================================================
# 2 - IDENTITY THREAT ANALYST
# ============================================================

identity_agent = Agent[IncidentState](
    name="Identity Threat Analyst",

    instructions="""
Você é especialista em identidade, autenticação e comprometimento
de contas.

Analise especialmente:

- MFA inesperado;
- possível MFA fatigue;
- roubo ou uso de credenciais;
- tokens e sessões;
- persistência de identidade;
- risco de movimentação lateral;
- envio de mensagens não autorizado.

Diferencie tentativa de ataque de comprometimento confirmado.

Nunca declare comprometimento sem evidência.

Produza WarRoomAnalysis.
""",

    output_type=WarRoomAnalysis,
    model=incident_commander.model,
)


# ============================================================
# 3 - DIGITAL FORENSICS
# ============================================================

forensics_agent = Agent[IncidentState](
    name="Digital Forensics Analyst",

    instructions="""
Você é responsável por preservação e análise forense inicial.

Determine:

- quais logs precisam ser preservados;
- quais timestamps importam;
- quais artefatos podem desaparecer;
- quais evidências devem ser coletadas antes de alterações;
- quais dados são necessários para construir uma timeline;
- quais ações poderiam destruir evidências.

Não realize investigação imaginária.

Produza WarRoomAnalysis.
""",

    output_type=WarRoomAnalysis,
    model=incident_commander.model,
)


# ============================================================
# 4 - BUSINESS IMPACT
# ============================================================

impact_agent = Agent[IncidentState](
    name="Business Impact Analyst",

    instructions="""
Você avalia impacto operacional e prioridade.

Considere:

- número de usuários;
- criticidade dos serviços;
- disponibilidade parcial ou total;
- risco financeiro;
- impacto de segurança;
- possibilidade de expansão;
- continuidade do negócio.

Avalie se P1/P2/P3/P4 está coerente.

Não eleve prioridade apenas porque o incidente parece dramático.

Produza WarRoomAnalysis.
""",

    output_type=WarRoomAnalysis,
    model=incident_commander.model,
)


# ============================================================
# 5 - RECOVERY PLANNER
# ============================================================

recovery_agent = Agent[IncidentState](
    name="Recovery Planner",

    instructions="""
Você planeja contenção e recuperação segura.

Separe claramente:

- contenção imediata;
- investigação;
- correção;
- recuperação;
- validação pós-recuperação.

Evite mudanças destrutivas antes de preservar evidências.

Inclua rollback quando aplicável.

Produza WarRoomAnalysis.
""",

    output_type=WarRoomAnalysis,
    model=incident_commander.model,
)


# ============================================================
# 6 - CHANGE RISK
# ============================================================

change_agent = Agent[IncidentState](
    name="Change Risk Analyst",

    instructions="""
Você atua como Change Manager técnico durante incidentes.

Analise quais mudanças propostas:

- são seguras agora;
- precisam de aprovação;
- devem aguardar evidências;
- apresentam risco de indisponibilidade;
- podem destruir evidências;
- precisam de rollback.

Sua função é impedir troubleshooting impulsivo.

Produza WarRoomAnalysis.
""",

    output_type=WarRoomAnalysis,
    model=incident_commander.model,
)


# ============================================================
# 7 - COMMUNICATIONS
# ============================================================

communications_agent = Agent[IncidentState](
    name="Incident Communications",

    instructions="""
Você cuida da comunicação durante o incidente.

Determine:

- o que comunicar ao usuário;
- o que comunicar ao Service Desk;
- o que comunicar ao SOC;
- o que comunicar à gestão;
- quais informações ainda não devem ser tratadas como fato.

Evite linguagem alarmista.

Produza WarRoomAnalysis.
""",

    output_type=WarRoomAnalysis,
    model=incident_commander.model,
)


# ============================================================
# 8 - SKEPTIC / RED TEAM
# ============================================================

skeptic_agent = Agent[IncidentState](
    name="Skeptic Red Team",

    instructions="""
Você é o revisor adversarial da War Room.

Sua função NÃO é concordar com os outros agentes.

Procure:

- conclusões sem evidência;
- correlações fracas;
- contradições;
- prioridade exagerada;
- prioridade subestimada;
- ações perigosas;
- evidências ausentes;
- vieses de confirmação;
- hipóteses tratadas como fatos.

Se a conclusão estiver boa, diga por quê.
Se estiver ruim, desafie explicitamente.

Produza AdversarialReview.
""",

    output_type=AdversarialReview,
    model=incident_commander.model,
)


# ============================================================
# 9 - FINAL COMMANDER
# ============================================================

final_commander = Agent[IncidentState](
    name="War Room Commander",

    instructions="""
Você é a autoridade final da War Room.

Você receberá:

1. investigação operacional;
2. análises especializadas;
3. revisão adversarial.

Sua função é produzir a decisão final.

Você NÃO deve simplesmente combinar textos.

Resolva conflitos entre os agentes.

Priorize evidência sobre opinião.

Separe fatos de hipóteses.

Se o Red Team encontrar uma falha válida, corrija a conclusão.

P1 exige evidência objetiva de criticidade, ataque ativo,
comprometimento confirmado ou indisponibilidade crítica.

Produza WarRoomDecision.
""",

    output_type=WarRoomDecision,
    model=incident_commander.model,
)


# ============================================================
# HELPER
# ============================================================

async def run_specialist(
    agent,
    report_text,
    state,
):

    prompt = f"""
INCIDENT ID:
{state.incident_id}

RELATÓRIO DA INVESTIGAÇÃO OPERACIONAL:

{report_text}

Realize sua análise especializada.
"""

    result = await Runner.run(
        agent,
        prompt,
        context=state,
        hooks=hooks,
    )

    return result.final_output


# ============================================================
# PRINT
# ============================================================

def print_decision(decision: WarRoomDecision):

    print("\n")
    print("=" * 80)
    print("SUPPORTOPS WAR ROOM - FINAL DECISION")
    print("=" * 80)

    print(f"Incident ID : {decision.incident_id}")
    print(f"Prioridade  : {decision.priority}")
    print(f"Confiança   : {decision.confidence}")

    print("\nRESUMO EXECUTIVO")
    print(decision.executive_summary)

    print("\nFATOS CONFIRMADOS")
    for item in decision.confirmed_facts:
        print(f"  + {item}")

    print("\nHIPÓTESES ABERTAS")
    for item in decision.open_hypotheses:
        print(f"  ? {item}")

    print("\nCONTRADIÇÕES")
    for item in decision.contradictions:
        print(f"  ! {item}")

    print("\nCONTENÇÃO DE SEGURANÇA")
    for item in decision.security_containment:
        print(f"  -> {item}")

    print("\nPRESERVAÇÃO DE EVIDÊNCIAS")
    for item in decision.evidence_preservation:
        print(f"  -> {item}")

    print("\nPLANO DE INVESTIGAÇÃO")
    for index, item in enumerate(
        decision.investigation_plan,
        start=1,
    ):
        print(f"  {index}. {item}")

    print("\nPLANO DE RECUPERAÇÃO")
    for item in decision.recovery_plan:
        print(f"  -> {item}")

    print("\nMUDANÇAS A EVITAR")
    for item in decision.changes_to_avoid:
        print(f"  X {item}")

    print("\nESCALONAMENTO")
    for item in decision.escalation:
        print(f"  -> {item}")

    print("\nCRITÉRIOS PARA P1")
    for item in decision.p1_triggers:
        print(f"  -> {item}")

    print("\nCRITÉRIOS PARA SEPARAR INCIDENTES")
    for item in decision.split_incident_criteria:
        print(f"  -> {item}")

    print("\nCOMUNICAÇÃO EXECUTIVA")
    print(decision.executive_message)


# ============================================================
# MAIN
# ============================================================

async def main():

    session = SQLiteSession(
        "supportops-warroom-session",
        "support_memory.db",
    )

    print("=" * 80)
    print("SUPPORTOPS WAR ROOM")
    print("Hierarchical Multi-Agent Incident Orchestration")
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
            "WAR-"
            + uuid.uuid4().hex[:8].upper()
        )

        state = IncidentState(
            incident_id=incident_id
        )

        initial_prompt = f"""
Incident ID: {incident_id}

Incidente:

{user_input}
"""

        print("\n" + "=" * 80)
        print("FASE 1 - TRIAGEM E INVESTIGAÇÃO")
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
            print("\nCASO DE ÁREA ÚNICA")
            print(core_result.final_output)
            continue

        core_report = core_result.final_output

        report_text = core_report.model_dump_json(
            indent=2
        )

        print("\n" + "=" * 80)
        print("FASE 2 - WAR ROOM PARALELA")
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
                run_specialist(
                    agent,
                    report_text,
                    state,
                )
                for agent in specialist_agents
            ]
        )

        analyses_text = "\n\n".join(
            analysis.model_dump_json(indent=2)
            for analysis in analyses
        )

        print("\n" + "=" * 80)
        print("FASE 3 - RED TEAM")
        print("=" * 80)

        skeptic_prompt = f"""
INCIDENT ID:
{incident_id}

INVESTIGAÇÃO ORIGINAL:

{report_text}

ANÁLISES DA WAR ROOM:

{analyses_text}

Faça uma revisão adversarial completa.
"""

        skeptic_result = await Runner.run(
            skeptic_agent,
            skeptic_prompt,
            context=state,
            hooks=hooks,
        )

        adversarial_review = (
            skeptic_result.final_output
        )

        print("\n" + "=" * 80)
        print("FASE 4 - DECISÃO FINAL")
        print("=" * 80)

        final_prompt = f"""
INCIDENT ID:
{incident_id}

RELATÓRIO OPERACIONAL:

{report_text}

ANÁLISES ESPECIALIZADAS:

{analyses_text}

REVISÃO ADVERSARIAL:

{
    adversarial_review.model_dump_json(
        indent=2
    )
}

Produza a decisão final da War Room.
"""

        final_result = await Runner.run(
            final_commander,
            final_prompt,
            context=state,
            hooks=hooks,
        )

        decision = final_result.final_output

        print_decision(decision)

        print("\n" + "=" * 80)
        print("ORQUESTRAÇÃO")
        print("=" * 80)

        print("\nAgentes executados:")
        for agent_name in state.agents_started:
            print(f"  -> {agent_name}")

        print("\nHandoffs:")
        for handoff_item in state.handoffs:
            print(f"  -> {handoff_item}")

        print("\nTools:")
        for tool_name in state.tools_called:
            print(f"  -> {tool_name}")

        print("\n" + "=" * 80)
        print("WAR ROOM ENCERRADA")
        print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())