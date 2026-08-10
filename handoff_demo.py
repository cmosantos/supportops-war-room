import asyncio

from agents import Agent, Runner, SQLiteSession, handoff

# Reaproveitamos os agentes que já construímos ontem.
from agente import infra_agent, m365_agent, security_agent


handoff_router = Agent(
    name="Support Handoff Router",

    instructions="""
Você é o agente de triagem de uma equipe de suporte de TI.

Sua função é analisar o problema apresentado pelo usuário e transferir
o atendimento para o especialista mais adequado.

Use os seguintes critérios:

- Problemas de Outlook, Exchange, Microsoft 365, caixas compartilhadas,
  permissões ou Teams devem ser transferidos para o especialista M365.

- Problemas de servidores, lentidão, armazenamento, CPU, memória,
  rede ou infraestrutura devem ser transferidos para o especialista
  de Infraestrutura.

- Problemas de MFA, login suspeito, autenticação, credenciais,
  tentativa de invasão ou risco de segurança devem ser transferidos
  para o especialista de Segurança.

Não tente resolver sozinho quando houver um especialista adequado.
Faça o handoff para o agente correto.
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
],

    # Usa a mesma configuração de modelo dos agentes existentes.
    model=security_agent.model,
)


async def main():

    session = SQLiteSession(
        "support-handoff-lab",
        "support_memory.db",
    )

    print("=" * 60)
    print("SUPPORT OPS - HANDOFF LAB")
    print("=" * 60)
    print("Digite 'sair' para encerrar.\n")

    while True:

        user_input = input("Você: ").strip()

        if user_input.lower() in {"sair", "exit", "quit"}:
            print("Encerrando...")
            break

        if not user_input:
            continue

        result = await Runner.run(
            handoff_router,
            user_input,
            session=session,
        )

        print()
        print("Resposta:")
        print(result.final_output)

        print()
        print(f"[Agente que terminou: {result.last_agent.name}]")
        print("-" * 60)


if __name__ == "__main__":
    asyncio.run(main())