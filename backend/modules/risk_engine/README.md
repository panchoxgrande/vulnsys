# Motor de Riesgo

Este módulo contendrá la lógica para calcular el riesgo de los activos.

## Algoritmo de Scoring de Riesgo

El cálculo del `risk_score` se basará en la siguiente fórmula:

```
risk_score = (CVSS_base * 10) * asset_criticality_multiplier * exploit_factor
```

Donde:
- **CVSS_base**: El score base de la vulnerabilidad (CVE).
- **asset_criticality_multiplier**: Un factor basado en la criticidad del tipo de activo.
  - `server`: 2.0
  - `workstation`: 1.0
- **exploit_factor**: Un factor basado en la disponibilidad de un exploit público.
  - `exploit público`: 1.5
  - `sin exploit`: 1.0
