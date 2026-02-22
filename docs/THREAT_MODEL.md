# Threat Model

## Protected Assets

- Security and compliance findings
- Identity and access metadata
- Operational logs and policy decisions

## Trust Boundaries

1. CLI/API inputs
2. External API integrations and web calls
3. Local report files and serialized logs

## Key Threats

- Input manipulation and malformed payloads
- Broken policy checks causing false negatives
- Credential leakage in logs or config
- Weak integrity guarantees in audit records

## Mitigations

- Input validation in core decision paths
- Test coverage for deny/allow edge cases
- Environment-based secret loading only
- CI gate requiring tests on every push/PR
