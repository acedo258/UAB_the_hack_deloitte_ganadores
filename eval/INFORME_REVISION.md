## Estado de la evaluación — 07/11/2026

**Responsable:** Equipo D — Criterio y evaluación

**Estado:** Gold Dataset provisional, pendiente de validación final de algunos casos.

Se han seleccionado y revisado 40 alertas representativas del dataset de Tarvia Group. Para cada caso se propone un veredicto, una severidad, una decisión de escalado y, cuando corresponde, una agrupación de incidente.

### Primera ejecución del evaluador (modo mock)

- Veredictos correctos: 22/40 (55 %).
- Severidad exacta: 22/40 (55 %).
- Severidad con tolerancia ±1: 39/40 (98 %).
- Escalado correcto: 39/40 (98 %).
- Incidentes reales clasificados como benignos o falsos positivos: 0.

**Estos resultados corresponden al simulador mock, no al agente IA real.** Su propósito es comprobar que el evaluador funciona.

### Trabajo pendiente

- Confirmar las severidades y los casos dudosos identificados en el informe.
- Evaluar el agente real desarrollado por B.
- Revisar los patrones de alertas.
- Implementar la correlación de incidentes.
- Preparar las métricas finales para el jurado.

El Gold Dataset es exclusivamente material de evaluación y no debe utilizarse para ajustar directamente los prompts ni las reglas del agente.

# Revisión de los 40 contextos — Deloitte Hackathon

Se han leído los 40 JSON del ZIP. Errores de extracción: Sin errores.

## Resultado de la revisión preliminar

- 35 casos con evidencia directa y clasificación propuesta de alta confianza.
- 1 caso(s) de confianza media; 4 requieren comprobación adicional.
- Distribución propuesta: 32 true_positive, 7 benign_true_positive, 1 false_positive.
- Los 40 son propuestas de analista, **no etiquetas validadas automáticamente** ni resultados del LLM.
- Las severidades se han calculado desde la tabla MATRIX de core/policy.py, asumiendo criticidad Media cuando no hay activos en el pack y un ajuste +1 en los casos con ejecución/acceso confirmado. La definición de este ajuste exige interpretación técnica y debe contrastarse con la política de Deloitte antes de congelar el gold.

## Casos que revisaría antes de dar por cerrado

1. **ALR-20261010-011798**: EDR indica `blocked`, pero los registros muestran procesos `vssadmin` y `wbadmin`. No bajar severidad por bloqueo sin confirmar ausencia de efecto.
2. **ALR-20261021-011900**: `related_events` está vacío; el dominio parece C2 por la campaña TPV, pero hay que recuperar registros de proxy/firewall concretos.
3. **ALR-20261008-011823**: acceso a pedido de otro cliente bloqueado, pero códigos internos expuestos después. Decidir severidad según tratamiento de datos y el alcance de la filtración.
4. **ALR-20261012-003200**: Puppeteer conocido, solo `PATH`/`HOME`. He propuesto `false_positive` (no hay lectura de secretos), confirmar definición de falso positivo frente a benign true positive con Deloitte.
5. **ALR-20261007-011786** y **ALR-20261007-011787**: los dos casos previos estaban anotados como `high`; la política puede elevar a `critical` por acceso real confirmado y regla high. **No sobrescribir el gold existente sin resolver esta discrepancia.**

## Limitaciones y buenas prácticas

- Algunos contextos indican `timeline recortada`; ausencia de alertas o eventos en el pack **no prueba** ausencia en la base completa.
- `matching_changes` es útil, pero se deben comprobar horario, origen, destino y alcance de cada cambio.
- La agrupación `INC-LAURA` etc. es **manual y provisional**: `eval/score.py` actualmente no evalúa `group`.
- El conjunto incluye 8 casos de control (7 BEN/1 FP); si el objetivo exige 10 ejemplos de ruido/benignos, faltan dos.
- No copiar estas respuestas a los prompts, código de decisión o entrenamiento. Mantener la revisión apartada del trabajo del agente.
- No ejecutar `git add .` sobre archivos temporales de contexto.

## Archivos

- `revision_40.csv`: revisión y evidencias por cada alerta.
- `gold_PROPUESTA_NO_VALIDADA.jsonl`: archivo de **candidatos** con esquema compatible. No sustituir aún a `eval/gold.jsonl`.
