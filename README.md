# 🔒 Verificador de Seguridad Windows - v3.0

**Auditoría profesional de seguridad basada en ISO/IEC 27001:2022 y 27002:2022**

![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Version](https://img.shields.io/badge/Version-3.0-blue)
![Python](https://img.shields.io/badge/Python-3.7+-green)
![Windows](https://img.shields.io/badge/Windows-10%2F11%2FServer-blue)
![License](https://img.shields.io/badge/License-MIT-orange)

---

## ✨ Características v3.0

### 🎯 30 Controles Detallados
- **7 módulos** de verificación integrados
- **30 controles** técnicos específicos
- Mapeo directo a **4 normas ISO** (A.9, A.10, A.12, A.13)
- Verificación granular de cada aspecto de seguridad

### 📊 Reportes Profesionales
- **HTML interactivo** con visualización de progreso
- **JSON estructurado** para procesamiento automatizado
- Puntuación general + per-ISO
- 11+ hallazgos con severidad y recomendaciones

### 🔧 Sin Dependencias Externas
- Solo librerías estándar de Python
- Ejecución rápida (2-3 minutos)
- Compatible con cualquier Windows 10+
- Ejecutable directo sin instalaciones

### 🌐 Interfaz Bilingüe
- Completamente en español
- Mensajes claros y actionables
- Comandos exactos para solucionar

---

## 🚀 Inicio Rápido (30 segundos)

```bash
# OPCIÓN 1: Más simple (recomendado)
Doble clic en: EJECUTAR.bat
→ Se abre el reporte automáticamente

# OPCIÓN 2: Desde terminal
python veri.py

# OPCIÓN 3: PowerShell
cd ruta/a/veri
python veri.py
```

**Requisitos:**
- Windows 10/11 o Server 2016+
- Python 3.7+ ([descargar](https://www.python.org/downloads/))
- **Ejecutar como ADMINISTRADOR**

---

## 📋 Módulos de Verificación

### 1️⃣ **Políticas de Contraseñas** (ISO A.9.2)
6 controles detallados:
- ✓ Longitud mínima (≥12 caracteres)
- ✓ Complejidad requerida
- ✓ Caducidad (≤90 días)
- ✓ Historial (≥24)
- ✓ Bloqueo por intentos (≥5)
- ✓ Duración de bloqueo (≥30 min)

### 2️⃣ **Actualizaciones y Parches** (ISO A.12.6)
4 controles detallados:
- ✓ Windows Update automático
- ✓ Servicio WuAuServ ejecutándose
- ✓ Última actualización (≤30 días)
- ✓ KB críticos pendientes

### 3️⃣ **Firewall** (ISO A.13.1)
4 controles detallados:
- ✓ Firewall Dominio
- ✓ Firewall Privado
- ✓ Firewall Público
- ✓ Notificaciones

### 4️⃣ **Antimalware** (ISO A.12.2)
4 controles detallados:
- ✓ Defender habilitado
- ✓ Protección tiempo real
- ✓ Definiciones actualizadas
- ✓ Análisis programado

### 5️⃣ **Auditoría** (ISO A.12.4)
4 controles detallados:
- ✓ Registro de seguridad
- ✓ Auditoría de logon
- ✓ Tamaño de logs (≥512 MB)
- ✓ Retención (≥30 días)

### 6️⃣ **Usuarios y Cuentas** (ISO A.9.1)
5 controles detallados:
- ✓ Guest deshabilitada
- ✓ Administrator renombrada
- ✓ Cuentas de servicio
- ✓ Cuentas administrativas
- ✓ UAC habilitado

### 7️⃣ **Encriptación** (ISO A.10.2)
3 controles detallados:
- ✓ BitLocker
- ✓ NTFS (no FAT32)
- ✓ Cifrado en tránsito

---

## 📊 Ejemplo de Resultado

```
================================================================================
VERIFICADOR DE SEGURIDAD WINDOWS - ISO 27001/27002 v3.0 DETALLADO
================================================================================

[*] Políticas de Contraseñas... ✗ (NO_CUMPLE)
[*] Actualizaciones y Parches... ✗ (NO_CUMPLE)
[*] Firewall... ✗ (NO_CUMPLE)
[*] Antimalware... ✓ (CUMPLE)
[*] Auditoría y Registros... ✗ (NO_CUMPLE)
[*] Usuarios y Cuentas... ✗ (NO_CUMPLE)
[*] Encriptación... ✗ (NO_CUMPLE)

================================================================================
Puntuación General: 16%
Controles Cumplidos: 5/30

Puntuaciones por Norma ISO:
  ISO/IEC 27001 A.9: 0% (0/11)      ← Gestión de acceso
  ISO/IEC 27001 A.10: 0% (0/3)      ← Criptografía
  ISO/IEC 27001 A.12: 25% (3/12)    ← Operaciones
  ISO/IEC 27001 A.13: 50% (2/4)     ← Perímetro

Total de Hallazgos: 11
================================================================================
```

---

## 📈 Interpretación de Puntuaciones

| Rango | Estado | Acción |
|-------|--------|--------|
| **90-100%** | ✓ Excelente | Solo ajustes menores |
| **75-89%** | ✓ Bueno | Algunos ajustes recomendados |
| **60-74%** | ⚠ Aceptable | Varias mejoras necesarias |
| **40-59%** | ✗ Deficiente | Múltiples problemas significativos |
| **0-39%** | ✗ Crítico | Acción inmediata requerida |

---

## 🔧 Solución de Hallazgos

Cada hallazgo incluye:
1. **Título**: Qué está mal
2. **Descripción**: Detalles del problema
3. **Severidad**: CRÍTICO / ALTO / MEDIO / BAJO
4. **Norma ISO**: Referencia específica
5. **Recomendación**: Comando exacto para solucionar

### Ejemplo:
```
⚠ Longitud mínima de contraseña insuficiente
  Severidad: ALTO
  Descripción: Configurada: 0 caracteres. Recomendado: 12+
  Norma ISO: ISO/IEC 27001 A.9.2.1
  Recomendación: Ejecutar: net accounts /minpwlen:12
```

---

## 📄 Reportes Generados

### 1. `reporte_seguridad.html`
- Interfaz visual interactiva
- Gráficos de progreso por ISO
- Código de colores por severidad
- Detalles de cada hallazgo

**Se abre automáticamente** al terminar la ejecución.

### 2. `reporte_seguridad.json`
- Formato técnico estructurado
- Ideal para procesamiento automatizado
- Almacenamiento de histórico
- 398+ líneas de datos detallados

---

## 🛠️ Comandos Rápidos para Solucionar

```powershell
# CONTRASEÑAS
net accounts /minpwlen:12              # Longitud mínima
net accounts /maxpwage:90              # Caducidad
net accounts /uniquepw:24              # Historial
net accounts /lockoutthreshold:5       # Bloqueo intentos
net accounts /lockoutduration:30       # Duración bloqueo

# FIREWALL
netsh advfirewall set allprofiles state on  # Habilitar todos

# ANTIMALWARE
powershell -c 'Set-MpPreference -DisableRealtimeMonitoring $false'

# USUARIOS
net user Guest /active:no              # Deshabilitar Guest

# WINDOWS UPDATE
powershell -c 'Set-Service WuAuServ -StartupType Automatic; Start-Service WuAuServ'
```

---

## 📚 Documentación

- **CAMBIOS_V3.0.txt** - Qué hay de nuevo en esta versión
- **GUIA_COMPLETA.txt** - Manual detallado de uso
- **README.txt** - Información general
- **EMPIEZA_AQUI.txt** - Inicio rápido

---

## 🔐 Normas Implementadas

- **ISO/IEC 27001:2022** - Sistema de gestión de seguridad de la información
- **ISO/IEC 27002:2022** - Códigos de práctica de seguridad de la información
- **ISO/IEC 27035:2016** - Gestión de incidentes de seguridad

Mapeo específico:
- **A.9** - Control de acceso y gestión de identidades (11 controles)
- **A.10** - Criptografía (3 controles)
- **A.12** - Operaciones de seguridad (12 controles)
- **A.13** - Comunicaciones y perímetro (4 controles)

---

## 💻 Compatibilidad

- ✅ Windows 10 Home/Pro/Enterprise
- ✅ Windows 11 (todas las versiones)
- ✅ Windows Server 2016 o superior
- ✅ Python 3.7, 3.8, 3.9, 3.10, 3.11, 3.12
- ✅ Admin privileges required

---

## 📦 Archivos Incluidos

```
veri/
├── veri.py                    # Programa principal (v3.0)
├── EJECUTAR.bat               # Ejecutor Windows (recomendado)
├── README.txt                 # Información general
├── EMPIEZA_AQUI.txt          # Inicio rápido
├── CAMBIOS_V3.0.txt          # Novedades v3.0
├── GUIA_COMPLETA.txt         # Manual completo
├── .gitignore                # Configuración Git
└── reporte_seguridad.*       # Reportes generados (HTML + JSON)
```

---

## 🔄 Mejora Continua

### Plan Recomendado:

**Semana 1:** Resolver hallazgos CRÍTICOS (rojo)
**Semana 2-3:** Resolver hallazgos ALTO (naranja)
**Mes 1-2:** Resolver hallazgos MEDIO (amarillo)
**Mensual:** Ejecutar verificación regularmente
**Trimestral:** Revisión completa de seguridad

---

## 🐛 Troubleshooting

### Error: "Error de permiso denegado"
→ Ejecuta como **ADMINISTRADOR**

### Error: "Python no encontrado"
→ Instala Python desde https://www.python.org/downloads/
→ Marca "Add to PATH" durante instalación

### Error: "Archivo no encontrado"
→ Navega a la carpeta de `veri` antes de ejecutar

### No se abre el HTML automático
→ Abre manualmente `reporte_seguridad.html` con doble clic

---

## 📊 Estadísticas v3.0

- **Líneas de código:** 1200+
- **Controles:** 30 detallados
- **Normas ISO:** 4 mapeadas
- **Hallazgos posibles:** 30+
- **Tiempo ejecución:** 2-3 minutos
- **Tamaño JSON:** 400+ líneas
- **Interfaz HTML:** Completamente responsive

---

## 🤝 Contribuciones

Reportar problemas en:
- 📧 Issues en GitHub
- 📋 Sugerencias de mejora

---

## 📄 Licencia

MIT License - Uso libre con fines educativos y comerciales

---

## 📞 Información

**Repositorio:** https://github.com/DinoPattta/veri
**Versión:** 3.0
**Última actualización:** 30 de noviembre de 2025
**Desarrollador:** DinoPattta

---

## ⭐ Características Destacadas

✨ **30 controles detallados** → Cobertura completa
✨ **Sin dependencias** → Ejecutable independiente
✨ **Reportes profesionales** → HTML + JSON
✨ **ISO 27001 mapeado** → Cumplimiento normativo
✨ **Recomendaciones actionables** → Comandos exactos
✨ **Interfaz amigable** → Totalmente en español
✨ **Rápido y eficiente** → 2-3 minutos de ejecución

---

**¿Necesitas ayuda?** Consulta `GUIA_COMPLETA.txt` para documentación detallada.
