# Segurança e Governança

## Evidência antes da ação

O SupportOps War Room diferencia quatro categorias de informação:

1. fatos observados por tools;
2. relatos do usuário;
3. hipóteses técnicas;
4. lacunas de evidência.

Ações corretivas devem ser justificadas por evidência suficiente. Quando relato e evidência entram em conflito, o conflito deve ser mantido explícito na análise.

## Deterministic Policy Engine

O Policy Engine é implementado em código e não depende da decisão livre da LLM. Ele recebe ações propostas e aplica regras de elegibilidade.

Uma ação pode ser:

- `ALLOW`: elegível para seguir ao Human-in-the-Loop;
- `BLOCK`: interrompida antes da execução.

Isso cria uma fronteira clara entre recomendação e autoridade operacional.

## Human-in-the-Loop

Ações sensíveis usam aprovação humana obrigatória. Exemplos do laboratório:

- revogar sessões;
- resetar MFA;
- alterar permissões de mailbox;
- reiniciar servidor.

Mesmo quando a policy permite uma ação, a tool sensível não é executada sem aprovação explícita.

## Execution Adapters

A camada de adapters desacopla o plano de remediação das tools sensíveis. Essa separação facilita auditoria, validação de parâmetros e futura integração com serviços reais.

## Post-Action Validation

Após uma execução, o Validator avalia:

- quais ações realmente foram executadas;
- quais foram rejeitadas ou bloqueadas;
- se a condição de risco foi reduzida;
- qual risco residual permanece;
- qual próximo passo é recomendado.

## Laboratório versus produção

As ações deste repositório são simuladas. Uma versão de produção exigiria controles adicionais, como mínimo privilégio, identidade imutável por UPN/Object ID, gestão de segredos, idempotência, rollback, auditoria persistente e separação rigorosa entre operações read-only e write.
