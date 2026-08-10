# Arquitetura do SupportOps War Room

## Fluxo principal

```text
Incidente
  ↓
Support Router V3
  ↓ handoff
Incident Commander V3
  ↓
Security / Microsoft 365 / Infrastructure Investigation Leads
  ↓
Evidências coletadas por tools
  ↓
Specialist Swarm
  ↓
Timeline + Evidence Quality
  ↓
Skeptic Red Team
  ↓
Consensus Judge
  ↓
War Room Commander V4
  ↓
Remediation Planner V4
  ↓
Deterministic Policy Engine
  ↓
ALLOW / BLOCK
  ↓
Human Approval
  ↓
Execution Adapter
  ↓
Sensitive Tool
  ↓
Post-Action Validator
```

## Princípio de autoridade

A arquitetura separa raciocínio probabilístico de controle operacional determinístico.

- agentes e LLMs interpretam evidências e propõem ações;
- tools coletam dados ou encapsulam capacidades;
- o Commander consolida a decisão;
- o Planner transforma a decisão em ações propostas;
- o Policy Engine decide elegibilidade por regras em código;
- o humano autoriza ações sensíveis elegíveis;
- o Execution Adapter chama a tool de execução;
- o Validator verifica resultado e risco residual.

O objetivo é impedir que uma recomendação da LLM seja tratada automaticamente como autorização de mudança.

## Domínios de investigação

### Security / Identity
Investiga autenticação, MFA, sign-ins, sessões e sinais de comprometimento de identidade.

### Microsoft 365
Investiga permissões, caixas compartilhadas, message trace, regras e saúde do serviço.

### Infrastructure
Investiga status de servidores, performance, eventos e rede.

## Specialist Swarm

A camada de swarm permite análises paralelas e complementares:

- correlação;
- ameaça de identidade;
- forense digital;
- impacto de negócio;
- recuperação;
- risco de mudança;
- comunicação de incidente.

A saída do swarm é complementada por Timeline Analyst e Evidence Quality Analyst antes de passar pelo Red Team e pelo Consensus Judge.

## Observabilidade

A integração com LangSmith cria um root trace por incidente para acompanhar o fluxo completo. Runs filhos permitem analisar agentes, tools, latência, tokens, custo e entradas/saídas de cada etapa.
