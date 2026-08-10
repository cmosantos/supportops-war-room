import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from agents import (
    Agent,
    RunContextWrapper,
    function_tool,
    handoff,
)

from supportops_pro import (
    IncidentReport,
    OpsHooks,
)


# ============================================================
# ESTADO V3 / EVIDENCE REGISTRY
# ============================================================

class IncidentStateV3(BaseModel):
    incident_id: str
    route: str | None = None

    evidencias: list[dict[str, Any]] = Field(default_factory=list)

    agents_started: list[str] = Field(default_factory=list)
    handoffs: list[str] = Field(default_factory=list)
    tools_called: list[str] = Field(default_factory=list)

    security_involved: bool = False
    m365_involved: bool = False
    infra_involved: bool = False


# Mantém compatibilidade com a War Room V2
IncidentState = IncidentStateV3


def registrar_evidencia(
    ctx: RunContextWrapper[IncidentStateV3],
    area: str,
    source: str,
    status: str,
    data: dict,
):
    evidence = {
        "area": area,
        "source": source,
        "status": status,
        "collected_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "data": data,
    }

    ctx.context.evidencias.append(evidence)

    return evidence


def output_json(data: dict) -> str:
    return json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
    )


hooks = OpsHooks()


# ============================================================
# SECURITY TOOLS
# ============================================================

@function_tool
async def sec_resolver_identidade(
    ctx: RunContextWrapper[IncidentStateV3],
    usuario: str,
) -> str:
    """Resolve nome informado para uma identidade corporativa."""

    print(
        f"\n[DATA:SECURITY] Resolvendo identidade: {usuario}"
    )

    if "carlos" in usuario.lower():

        data = {
            "found": True,
            "display_name": "Carlos",
            "upn": "carlos@lab.local",
            "object_id": "USR-1042",
            "account_enabled": True,
            "source": "SIMULATED_DIRECTORY",
        }

        status = "success"

    else:

        data = {
            "found": False,
            "query": usuario,
            "source": "SIMULATED_DIRECTORY",
        }

        status = "not_found"

    registrar_evidencia(
        ctx,
        "security",
        "identity_directory",
        status,
        data,
    )

    return output_json(data)


@function_tool
async def sec_consultar_signins(
    ctx: RunContextWrapper[IncidentStateV3],
    usuario: str,
) -> str:
    """Consulta eventos de autenticação recentes do usuário."""

    print(
        f"\n[DATA:SECURITY] Consultando sign-ins: {usuario}"
    )

    data = {
        "user": usuario,
        "events": [
            {
                "time": "09:46",
                "device": "Notebook-Corporativo",
                "network": "rede_corporativa",
                "status": "success",
                "mfa": "satisfied",
                "risk": "low",
            },
            {
                "time": "09:49",
                "device": "Unknown-Device",
                "network": "rede_externa",
                "status": "failed",
                "mfa": "not_completed",
                "risk": "medium",
            },
            {
                "time": "09:51",
                "device": "Unknown-Device",
                "network": "rede_externa",
                "status": "success",
                "mfa": "approved_push",
                "risk": "high",
            },
        ],
        "source": "SIMULATED_ENTRA_SIGNINS",
    }

    registrar_evidencia(
        ctx,
        "security",
        "entra_signins",
        "success",
        data,
    )

    return output_json(data)


@function_tool
async def sec_consultar_mfa(
    ctx: RunContextWrapper[IncidentStateV3],
    usuario: str,
) -> str:
    """Consulta desafios e resultados MFA recentes."""

    print(
        f"\n[DATA:SECURITY] Consultando MFA: {usuario}"
    )

    data = {
        "user": usuario,
        "challenges": [
            {"time": "09:47", "result": "denied"},
            {"time": "09:48", "result": "denied"},
            {"time": "09:50", "result": "timeout"},
            {
                "time": "09:51",
                "result": "approved",
                "device": "Unknown-Device",
            },
        ],
        "source": "SIMULATED_MFA_LOG",
    }

    registrar_evidencia(
        ctx,
        "security",
        "mfa_log",
        "success",
        data,
    )

    return output_json(data)


@function_tool
async def sec_consultar_sessoes(
    ctx: RunContextWrapper[IncidentStateV3],
    usuario: str,
) -> str:
    """Consulta sessões ativas e dispositivos associados."""

    print(
        f"\n[DATA:SECURITY] Consultando sessões: {usuario}"
    )

    data = {
        "user": usuario,
        "sessions": [
            {
                "device": "Notebook-Corporativo",
                "created": "08:12",
                "status": "active",
                "known": True,
            },
            {
                "device": "Unknown-Device",
                "created": "09:51",
                "status": "active",
                "known": False,
            },
        ],
        "source": "SIMULATED_SESSION_STORE",
    }

    registrar_evidencia(
        ctx,
        "security",
        "active_sessions",
        "success",
        data,
    )

    return output_json(data)


# ============================================================
# MICROSOFT 365 TOOLS
# ============================================================

@function_tool
async def m365_consultar_permissoes(
    ctx: RunContextWrapper[IncidentStateV3],
    usuario: str,
    mailbox: str,
) -> str:
    """Consulta permissões diretas e efetivas da caixa compartilhada."""

    print(
        f"\n[DATA:M365] Permissões {usuario} -> {mailbox}"
    )

    data = {
        "user": usuario,
        "mailbox": mailbox,
        "direct_permissions": [],
        "group_membership": [
            "Financeiro-Delegados"
        ],
        "effective_permissions": {
            "FullAccess": True,
            "SendAs": True,
            "SendOnBehalf": False,
        },
        "source": "SIMULATED_EXCHANGE",
    }

    registrar_evidencia(
        ctx,
        "m365",
        "exchange_permissions",
        "success",
        data,
    )

    return output_json(data)


@function_tool
async def m365_message_trace(
    ctx: RunContextWrapper[IncidentStateV3],
    usuario: str,
    mailbox: str,
) -> str:
    """Consulta rastreamento de mensagens da caixa."""

    print(
        f"\n[DATA:M365] Message Trace: {mailbox}"
    )

    data = {
        "mailbox": mailbox,
        "messages": [
            {
                "time": "10:02",
                "sender": "FINANCEIRO",
                "recipient": "fornecedor@external.test",
                "status": "delivered",
                "authenticated_actor": usuario,
                "client": "Outlook Web",
                "session_device": "Unknown-Device",
            }
        ],
        "source": "SIMULATED_MESSAGE_TRACE",
    }

    registrar_evidencia(
        ctx,
        "m365",
        "message_trace",
        "success",
        data,
    )

    return output_json(data)


@function_tool
async def m365_consultar_regras(
    ctx: RunContextWrapper[IncidentStateV3],
    usuario: str,
) -> str:
    """Consulta regras e encaminhamentos recentes."""

    print(
        f"\n[DATA:M365] Consultando regras: {usuario}"
    )

    data = {
        "user": usuario,
        "rules": [
            {
                "name": "RSS Updates",
                "created": "10:04",
                "action": "forward",
                "destination": "external-address@test.invalid",
                "known": False,
            }
        ],
        "source": "SIMULATED_MAILBOX_AUDIT",
    }

    registrar_evidencia(
        ctx,
        "m365",
        "mailbox_rules",
        "success",
        data,
    )

    return output_json(data)


@function_tool
async def m365_service_health(
    ctx: RunContextWrapper[IncidentStateV3],
) -> str:
    """Consulta saúde geral dos serviços Microsoft 365."""

    print(
        "\n[DATA:M365] Consultando Service Health"
    )

    data = {
        "exchange_online": "healthy",
        "outlook": "healthy",
        "active_incidents": [],
        "source": "SIMULATED_SERVICE_HEALTH",
    }

    registrar_evidencia(
        ctx,
        "m365",
        "service_health",
        "success",
        data,
    )

    return output_json(data)


# ============================================================
# INFRA TOOLS
# ============================================================

@function_tool
async def infra_consultar_status(
    ctx: RunContextWrapper[IncidentStateV3],
    servidor: str,
) -> str:
    """Consulta disponibilidade básica do servidor."""

    print(
        f"\n[DATA:INFRA] Status do servidor: {servidor}"
    )

    data = {
        "server": servidor,
        "reachable": True,
        "service_state": "online",
        "source": "SIMULATED_MONITORING",
    }

    registrar_evidencia(
        ctx,
        "infra",
        "server_status",
        "success",
        data,
    )

    return output_json(data)


@function_tool
async def infra_metricas_performance(
    ctx: RunContextWrapper[IncidentStateV3],
    servidor: str,
) -> str:
    """Consulta CPU, memória, disco e fila SMB."""

    print(
        f"\n[DATA:INFRA] Métricas: {servidor}"
    )

    data = {
        "server": servidor,
        "cpu_percent": 38,
        "memory_percent": 64,
        "disk_latency_ms": 82,
        "smb_queue": "high",
        "storage_latency_ms": 110,
        "window": "09:55-10:25",
        "source": "SIMULATED_ZABBIX",
    }

    registrar_evidencia(
        ctx,
        "infra",
        "performance_metrics",
        "success",
        data,
    )

    return output_json(data)


@function_tool
async def infra_eventos(
    ctx: RunContextWrapper[IncidentStateV3],
    servidor: str,
) -> str:
    """Consulta eventos relevantes do servidor."""

    print(
        f"\n[DATA:INFRA] Event logs: {servidor}"
    )

    data = {
        "server": servidor,
        "events": [
            {
                "time": "10:01",
                "type": "storage_latency_warning",
            },
            {
                "time": "10:07",
                "type": "smb_timeout",
            },
            {
                "time": "10:13",
                "type": "smb_timeout",
            },
        ],
        "security_events_related_to_carlos": [],
        "source": "SIMULATED_EVENT_LOG",
    }

    registrar_evidencia(
        ctx,
        "infra",
        "event_log",
        "success",
        data,
    )

    return output_json(data)


@function_tool
async def infra_consultar_rede(
    ctx: RunContextWrapper[IncidentStateV3],
    servidor: str,
) -> str:
    """Consulta indicadores básicos de rede."""

    print(
        f"\n[DATA:INFRA] Rede: {servidor}"
    )

    data = {
        "server": servidor,
        "packet_loss_percent": 0.1,
        "latency_ms": 3,
        "interface_errors": 0,
        "status": "normal",
        "source": "SIMULATED_NETWORK_MONITORING",
    }

    registrar_evidencia(
        ctx,
        "infra",
        "network_metrics",
        "success",
        data,
    )

    return output_json(data)


# ============================================================
# SPECIALIST AGENTS V3
# ============================================================

security_agent = Agent[IncidentStateV3](
    name="Security Investigation Lead",

    instructions="""
Você é o especialista de Segurança e Identidade.

Para incidentes de identidade relevantes, investigue com ferramentas.

Quando houver MFA suspeito, possível login ou comprometimento:
1. resolva a identidade;
2. consulte sign-ins;
3. consulte MFA;
4. consulte sessões.

Cruze horários, dispositivos e resultados.

Não trate MFA recebido como comprometimento confirmado.
Não ignore uma autenticação bem-sucedida em dispositivo desconhecido.
""",

    tools=[
        sec_resolver_identidade,
        sec_consultar_signins,
        sec_consultar_mfa,
        sec_consultar_sessoes,
    ],
)


m365_agent = Agent[IncidentStateV3](
    name="Microsoft 365 Investigation Lead",

    instructions="""
Você é especialista em Microsoft 365 e Exchange.

Quando houver caixa compartilhada ou mensagem suspeita:
- consulte permissões efetivas;
- consulte message trace;
- consulte regras/encaminhamentos;
- consulte Service Health.

Diferencie permissão direta de permissão herdada por grupo.

Correlacione authenticated_actor, dispositivo e horário
com os demais dados quando disponíveis.
""",

    tools=[
        m365_consultar_permissoes,
        m365_message_trace,
        m365_consultar_regras,
        m365_service_health,
    ],
)


infra_agent = Agent[IncidentStateV3](
    name="Infrastructure Investigation Lead",

    instructions="""
Você é especialista em infraestrutura.

Quando houver lentidão de servidor:
- consulte disponibilidade;
- métricas de performance;
- event logs;
- rede.

Servidor ONLINE não significa servidor saudável.

Diferencie problema de CPU, memória, storage, SMB e rede.
Busque também evidência que conecte ou separe o evento
de possíveis incidentes de identidade.
""",

    tools=[
        infra_consultar_status,
        infra_metricas_performance,
        infra_eventos,
        infra_consultar_rede,
    ],
)


# ============================================================
# AGENTS AS TOOLS
# ============================================================

security_tool = security_agent.as_tool(
    tool_name="investigate_security",
    tool_description=(
        "Executa investigação aprofundada de identidade, "
        "MFA, sign-ins e sessões."
    ),
    hooks=hooks,
)


m365_tool = m365_agent.as_tool(
    tool_name="investigate_m365",
    tool_description=(
        "Executa investigação aprofundada de Exchange "
        "e Microsoft 365."
    ),
    hooks=hooks,
)


infra_tool = infra_agent.as_tool(
    tool_name="investigate_infrastructure",
    tool_description=(
        "Executa investigação aprofundada de servidores "
        "e infraestrutura."
    ),
    hooks=hooks,
)


# ============================================================
# INCIDENT COMMANDER V3
# ============================================================

incident_commander = Agent[IncidentStateV3](
    name="Incident Commander V3",

    instructions="""
Você coordena incidentes multidisciplinares.

Acione todos os especialistas relevantes.

Para incidentes envolvendo simultaneamente:
- identidade/MFA;
- Microsoft 365;
- infraestrutura;

chame os três especialistas.

A investigação deve buscar evidências técnicas e correlação.

IMPORTANTE:

Uma autenticação bem-sucedida com MFA aprovado em dispositivo
desconhecido aumenta substancialmente o risco.

Uma mensagem enviada pela mesma identidade/sessão pode fortalecer
a correlação entre identidade e Microsoft 365.

Problemas de storage/SMB sem indicadores compartilhados podem ser
um incidente independente.

Nunca force correlação.

Prioridade:
P1 apenas com comprometimento/ataque ativo ou impacto crítico.
P2 para comprometimento provável ou impacto relevante em investigação.
P3 para impacto limitado.
P4 informativo.

Gere IncidentReport estruturado.
""",

    tools=[
        m365_tool,
        infra_tool,
        security_tool,
    ],

    output_type=IncidentReport,
)


# ============================================================
# ROUTER V3
# ============================================================

hybrid_router = Agent[IncidentStateV3](
    name="Support Router V3",

    instructions="""
Faça triagem.

Uma área:
-> especialista correspondente.

Duas ou mais áreas:
-> Incident Commander V3.

Segurança combinada com qualquer problema operacional:
-> Incident Commander V3.
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
)