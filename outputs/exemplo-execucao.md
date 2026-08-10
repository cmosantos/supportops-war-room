# Exemplo de execução

## Decisão consolidada

```text
Prioridade       : P2
Confiança        : alta
Consensus Score  : 90/100
Evidence Score   : 86/100
Security Risk    : 78/100
```

## Interpretação

O laboratório concluiu que os eventos de identidade e Microsoft 365 eram provavelmente parte do mesmo incidente de segurança, enquanto a degradação do `SRV-ARQUIVOS` apresentava sinais de um incidente independente de storage/SMB.

## Policy Engine

```text
A1 revoke_sessions              -> ALLOW
A2 reset_mfa                    -> BLOCK
A3 change_mailbox_permission    -> BLOCK
A4 restart_server               -> BLOCK
```

Apenas `A1` avançou para aprovação humana. Após aprovação, a execução simulada foi realizada.

## Validação pós-ação

O resultado permaneceu `partial`, pois somente uma ação foi executada e o ambiente é simulado. O Validator manteve risco residual e recomendou executar as ações aprovadas em um ambiente real com controles apropriados.

Este exemplo demonstra que o Planner pode propor várias ações, mas somente ações elegíveis pela policy chegam ao Human-in-the-Loop.
