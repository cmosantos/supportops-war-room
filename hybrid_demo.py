import asyncio

from agents import Agent, Runner, SQLiteSession, handoff

from agente import (
    infra_agent,
    m365_agent,
    security_agent,
    infra_tool,
    m365_tool,
    security_tool,
)


# ============================================================
# INCIDENT COMMANDER
# ============================================================

incident_commander = Agent(
    name="Incident Commander",

    instructions="""
Você é o Incident Commander de uma operação corporativa de suporte de TI.

Você recebe incidentes que podem envolver múltiplas áreas ao mesmo tempo.

Especialistas disponíveis:
- Microsoft 365
- Infraestrutura
- Segurança

Sua função NÃO é simplesmente escolher um especialista.
Sua função é coordenar a investigação.

REGRAS:

1. Identifique todas as áreas envolvidas.

2. Consulte todos os especialistas relevantes usando suas ferramentas.

3. Se o incidente mencionar explicitamente:
   - Outlook, Exchange, Microsoft 365, Teams ou caixa compartilhada:
     consulte Microsoft 365.

   - servidor, CPU, memória, disco, rede, lentidão ou armazenamento:
     consulte Infraestrutura.

   - MFA, login suspeito, credenciais, autenticação ou invasão:
     consulte Segurança.

4. Um incidente pode exigir MAIS DE UMA ferramenta.

5. Nunca invente evidências que as ferramentas não confirmaram.

6. Diferencie claramente:
   - fatos confirmados;
   - hipóteses;
   - falhas de consulta.

7. Se houver possível comprometimento de segurança junto com problema
   operacional, priorize contenção de segurança antes de mudanças
   administrativas ou troubleshooting invasivo.

8. Correlacione os resultados. Não apenas copie respostas dos especialistas.

Sua resposta final deve conter:

## Resumo do incidente

## Evidências
- Microsoft 365
- Infraestrutura
- Segurança

## Correlação e análise de risco

## Prioridade

## Próxima ação recomendada

## Escalonamento

Se algum especialista não conseguir obter evidências, deixe isso explícito.
""",

    tools=[
        m365_tool,
        infra_tool,
        security_tool,
    ],

    model=security_agent.model,
)


# ============================================================
# ROUTER HÍBRIDO
# ============================================================

hybrid_router = Agent(
    name="Support Hybrid Router",

    instructions="""
Você realiza a triagem inicial de incidentes de TI.

Existem quatro destinos possíveis:

1. Microsoft 365
2. Infraestrutura
3. Segurança
4. Incident Commander

Use handoff direto para um especialista quando o incidente for claramente
de UMA única área.

Exemplos:

Problema apenas de Outlook ou Exchange:
→ Microsoft 365

Problema apenas de servidor ou infraestrutura:
→ Infraestrutura

Problema apenas de MFA ou segurança:
→ Segurança

IMPORTANTE:

Se o incidente envolver DUAS OU MAIS áreas, ou houver necessidade de
correlacionar eventos diferentes, transfira para o Incident Commander.

Se houver um possível incidente de segurança combinado com qualquer
outro problema operacional, prefira o Incident Commander.

Não tente resolver incidentes complexos sozinho.
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
# EXECUÇÃO
# ============================================================

async def main():

    session = SQLiteSession(
        "support-hybrid-lab",
        "support_memory.db",
    )

    print("=" * 70)
    print("SUPPORT OPS - HYBRID MULTI-AGENT LAB")
    print("=" * 70)
    print("Handoff + Agents as Tools + Memory")
    print("Digite 'sair' para encerrar.\n")

    while True:

        user_input = input("Você: ").strip()

        if user_input.lower() in {"sair", "exit", "quit"}:
            print("Encerrando...")
            break

        if not user_input:
            continue

        result = await Runner.run(
            hybrid_router,
            user_input,
            session=session,
        )

        print("\n" + "=" * 70)
        print("RESPOSTA FINAL")
        print("=" * 70)

        print(result.final_output)

        print("\n" + "-" * 70)
        print(f"Agente final: {result.last_agent.name}")
        print("-" * 70)


if __name__ == "__main__":
    asyncio.run(main())