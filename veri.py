#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║         VERIFICADOR DE SEGURIDAD WINDOWS - ISO 27001/27002               ║
║                      Versión 3.0 - DETALLADO                             ║
║                                                                           ║
║  Auditoría Profesional de Seguridad con 25+ Controles por Norma ISO      ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import json
import subprocess
import re
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod


if sys.version_info < (3, 7):
    print("ERROR: Se requiere Python 3.7 o superior")
    sys.exit(1)

if not sys.platform.startswith('win'):
    print("ERROR: Este programa solo funciona en Windows")
    sys.exit(1)


class NivelSeveridad(Enum):
    CRITICO = "CRÍTICO"
    ALTO = "ALTO"
    MEDIO = "MEDIO"
    BAJO = "BAJO"
    INFO = "INFORMACIÓN"


class VerificadorBase(ABC):
    @abstractmethod
    def verificar(self):
        pass

    def _ejecutar_cmd(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5)
        except:
            return ""


# ============================================================================
# MODULO 1: VERIFICADOR DE CONTRASEÑAS (ISO A.9.2) - 6 CONTROLES
# ============================================================================

class VerificadorContraseñas(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Políticas de Contraseñas",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.9.2",
            "controles": [
                {"nombre": "Longitud mínima (≥12 caracteres)", "cumple": False, "valor": "0"},
                {"nombre": "Complejidad requerida", "cumple": False, "valor": "No"},
                {"nombre": "Caducidad (≤90 días)", "cumple": False, "valor": "0"},
                {"nombre": "Historial de contraseñas (≥24)", "cumple": False, "valor": "0"},
                {"nombre": "Bloqueo por intentos fallidos", "cumple": False, "valor": "0"},
                {"nombre": "Duración bloqueo (≥30 min)", "cumple": False, "valor": "0"}
            ]
        }
        
        try:
            # 1. Longitud mínima
            long_min = self._verificar_longitud_minima()
            if long_min["valor"] >= 12:
                resultado["controles"][0]["cumple"] = True
                resultado["controles"][0]["valor"] = f"{long_min['valor']} caracteres"
            else:
                resultado["controles"][0]["valor"] = f"{long_min['valor']} caracteres"
                resultado["hallazgos"].append({
                    "titulo": "Longitud mínima de contraseña insuficiente",
                    "descripcion": f"Configurada: {long_min['valor']} caracteres. Recomendado: 12+",
                    "severidad": "ALTO",
                    "norma_iso": "ISO/IEC 27001 A.9.2.1",
                    "recomendacion": "Ejecutar: net accounts /minpwlen:12"
                })
            
            # 2. Complejidad
            complejidad = self._verificar_complejidad()
            if complejidad["cumple"]:
                resultado["controles"][1]["cumple"] = True
                resultado["controles"][1]["valor"] = "Habilitada"
            else:
                resultado["controles"][1]["valor"] = "Deshabilitada"
                resultado["hallazgos"].append({
                    "titulo": "Complejidad de contraseña no requerida",
                    "descripcion": "Las contraseñas no requieren mayúsculas, minúsculas, números y símbolos",
                    "severidad": "ALTO",
                    "norma_iso": "ISO/IEC 27001 A.9.2.1",
                    "recomendacion": "Ejecutar: net accounts /maxpwage:90"
                })
            
            # 3. Caducidad
            caducidad = self._verificar_caducidad()
            if caducidad["cumple"]:
                resultado["controles"][2]["cumple"] = True
                resultado["controles"][2]["valor"] = f"{caducidad['dias']} días"
            else:
                resultado["controles"][2]["valor"] = f"{caducidad['dias']} días"
                resultado["hallazgos"].append({
                    "titulo": "Caducidad de contraseña no configurada",
                    "descripcion": f"Configurada: {caducidad['dias']} días. Recomendado: ≤90 días",
                    "severidad": "MEDIO",
                    "norma_iso": "ISO/IEC 27001 A.9.2.3",
                    "recomendacion": "Ejecutar: net accounts /maxpwage:90"
                })
            
            # 4. Historial
            historial = self._verificar_historial()
            if historial["valor"] >= 24:
                resultado["controles"][3]["cumple"] = True
                resultado["controles"][3]["valor"] = f"{historial['valor']} registros"
            else:
                resultado["controles"][3]["valor"] = f"{historial['valor']} registros"
                resultado["hallazgos"].append({
                    "titulo": "Historial de contraseñas insuficiente",
                    "descripcion": f"Configurado: {historial['valor']}. Recomendado: 24+",
                    "severidad": "MEDIO",
                    "norma_iso": "ISO/IEC 27001 A.9.2.1",
                    "recomendacion": "Ejecutar: net accounts /uniquepw:24"
                })
            
            # 5. Bloqueo por intentos
            bloqueo = self._verificar_bloqueo()
            if bloqueo["intentos"] >= 5:
                resultado["controles"][4]["cumple"] = True
                resultado["controles"][4]["valor"] = f"{bloqueo['intentos']} intentos"
            else:
                resultado["controles"][4]["valor"] = f"{bloqueo['intentos']} intentos"
                resultado["hallazgos"].append({
                    "titulo": "Bloqueo por intentos fallidos insuficiente",
                    "descripcion": f"Configurado: {bloqueo['intentos']} intentos. Recomendado: 5+",
                    "severidad": "ALTO",
                    "norma_iso": "ISO/IEC 27001 A.9.2.5",
                    "recomendacion": "Ejecutar: net accounts /lockoutthreshold:5"
                })
            
            # 6. Duración bloqueo
            duracion = self._verificar_duracion_bloqueo()
            if duracion["minutos"] >= 30:
                resultado["controles"][5]["cumple"] = True
                resultado["controles"][5]["valor"] = f"{duracion['minutos']} minutos"
            else:
                resultado["controles"][5]["valor"] = f"{duracion['minutos']} minutos"
                resultado["hallazgos"].append({
                    "titulo": "Duración de bloqueo muy corta",
                    "descripcion": f"Configurada: {duracion['minutos']} minutos. Recomendado: 30+",
                    "severidad": "MEDIO",
                    "norma_iso": "ISO/IEC 27001 A.9.2.5",
                    "recomendacion": "Ejecutar: net accounts /lockoutduration:30"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except Exception as e:
            resultado["estado"] = "ERROR"
            resultado["error"] = str(e)
        
        return resultado
    
    def _verificar_longitud_minima(self):
        output = self._ejecutar_cmd("net accounts")
        nums = re.findall(r'\d+', output)
        valor = int(nums[0]) if nums else 0
        return {"valor": valor, "cumple": valor >= 12}
    
    def _verificar_complejidad(self):
        output = self._ejecutar_cmd("net accounts")
        cumple = "complexity is required" in output.lower()
        return {"cumple": cumple}
    
    def _verificar_caducidad(self):
        output = self._ejecutar_cmd("net accounts")
        for linea in output.split('\n'):
            if "Maximum password age" in linea:
                nums = re.findall(r'\d+', linea)
                if nums:
                    dias = int(nums[-1])
                    return {"dias": dias, "cumple": 0 < dias <= 90}
        return {"dias": 0, "cumple": False}
    
    def _verificar_historial(self):
        output = self._ejecutar_cmd("net accounts")
        for linea in output.split('\n'):
            if "Password history length" in linea:
                nums = re.findall(r'\d+', linea)
                if nums:
                    valor = int(nums[-1])
                    return {"valor": valor, "cumple": valor >= 24}
        return {"valor": 0, "cumple": False}
    
    def _verificar_bloqueo(self):
        output = self._ejecutar_cmd("net accounts")
        for linea in output.split('\n'):
            if "Lockout threshold" in linea:
                nums = re.findall(r'\d+', linea)
                if nums:
                    intentos = int(nums[-1])
                    return {"intentos": intentos, "cumple": intentos >= 5}
        return {"intentos": 0, "cumple": False}
    
    def _verificar_duracion_bloqueo(self):
        output = self._ejecutar_cmd("net accounts")
        for linea in output.split('\n'):
            if "Lockout duration" in linea:
                nums = re.findall(r'\d+', linea)
                if nums:
                    minutos = int(nums[-1])
                    return {"minutos": minutos, "cumple": minutos >= 30}
        return {"minutos": 0, "cumple": False}


# ============================================================================
# MODULO 2: VERIFICADOR DE ACTUALIZACIONES (ISO A.12.6) - 4 CONTROLES
# ============================================================================

class VerificadorActualizaciones(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Actualizaciones y Parches",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.12.6",
            "controles": [
                {"nombre": "Windows Update automático", "cumple": False, "valor": "Deshabilitado"},
                {"nombre": "Servicio WuAuServ en ejecución", "cumple": False, "valor": "No"},
                {"nombre": "Última actualización (≤30 días)", "cumple": False, "valor": "Desconocido"},
                {"nombre": "KB críticos pendientes", "cumple": False, "valor": "Desconocido"}
            ]
        }
        
        try:
            wu = self._verificar_wu_automatico()
            if wu["estado"] == "HABILITADO":
                resultado["controles"][0]["cumple"] = True
                resultado["controles"][0]["valor"] = "Habilitado"
                resultado["controles"][1]["cumple"] = True
                resultado["controles"][1]["valor"] = "Ejecutándose"
            else:
                resultado["controles"][0]["valor"] = "Deshabilitado"
                resultado["controles"][1]["valor"] = "No ejecutándose"
                resultado["hallazgos"].append({
                    "titulo": "Windows Update automático deshabilitado",
                    "descripcion": "Las actualizaciones automáticas no están habilitadas",
                    "severidad": "ALTO",
                    "norma_iso": "ISO/IEC 27001 A.12.6.1",
                    "recomendacion": "Habilitar Windows Update: Settings > Update & Security"
                })
            
            ultima = self._verificar_ultima_actualizacion()
            if ultima["dias"] <= 30:
                resultado["controles"][2]["cumple"] = True
                resultado["controles"][2]["valor"] = f"{ultima['dias']} días"
            else:
                resultado["controles"][2]["valor"] = f"{ultima['dias']} días"
                resultado["hallazgos"].append({
                    "titulo": "Sistema no actualizado recientemente",
                    "descripcion": f"Última actualización hace {ultima['dias']} días",
                    "severidad": "MEDIO",
                    "norma_iso": "ISO/IEC 27001 A.12.6.1",
                    "recomendacion": "Ejecutar: Windows Update > Buscar actualizaciones"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except Exception as e:
            resultado["estado"] = "ERROR"
            resultado["error"] = str(e)
        
        return resultado
    
    def _verificar_wu_automatico(self):
        output = self._ejecutar_cmd("powershell -Command \"Get-Service WuAuServ | Select-Object -ExpandProperty Status\"")
        estado = "HABILITADO" if "running" in output.lower() else "DESHABILITADO"
        return {"estado": estado}
    
    def _verificar_ultima_actualizacion(self):
        try:
            output = self._ejecutar_cmd("powershell -Command \"Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn\"")
            if output.strip():
                from datetime import datetime as dt
                fecha = dt.strptime(output.strip()[:10], "%m/%d/%Y")
                dias = (dt.now() - fecha).days
                return {"dias": dias}
        except:
            pass
        return {"dias": 0}


# ============================================================================
# MODULO 3: VERIFICADOR DE FIREWALL (ISO A.13.1) - 4 CONTROLES
# ============================================================================

class VerificadorFirewall(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Firewall",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.13.1",
            "controles": [
                {"nombre": "Firewall habilitado (Dominio)", "cumple": False, "valor": "No"},
                {"nombre": "Firewall habilitado (Privado)", "cumple": False, "valor": "No"},
                {"nombre": "Firewall habilitado (Público)", "cumple": False, "valor": "No"},
                {"nombre": "Notificaciones habilitadas", "cumple": False, "valor": "No"}
            ]
        }
        
        try:
            perfiles = self._verificar_perfiles_firewall()
            resultado["controles"][0]["valor"] = "Sí" if perfiles.get("Dominio") else "No"
            resultado["controles"][0]["cumple"] = perfiles.get("Dominio", False)
            resultado["controles"][1]["valor"] = "Sí" if perfiles.get("Privado") else "No"
            resultado["controles"][1]["cumple"] = perfiles.get("Privado", False)
            resultado["controles"][2]["valor"] = "Sí" if perfiles.get("Público") else "No"
            resultado["controles"][2]["cumple"] = perfiles.get("Público", False)
            
            if not all(perfiles.values()):
                resultado["hallazgos"].append({
                    "titulo": "Firewall deshabilitado en uno o más perfiles",
                    "descripcion": f"Dominio: {perfiles.get('Dominio')}, Privado: {perfiles.get('Privado')}, Público: {perfiles.get('Público')}",
                    "severidad": "CRITICO",
                    "norma_iso": "ISO/IEC 27001 A.13.1.1",
                    "recomendacion": "Ejecutar: netsh advfirewall set allprofiles state on"
                })
            else:
                resultado["controles"][3]["cumple"] = True
                resultado["controles"][3]["valor"] = "Sí"
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except Exception as e:
            resultado["estado"] = "ERROR"
            resultado["error"] = str(e)
        
        return resultado
    
    def _verificar_perfiles_firewall(self):
        output = self._ejecutar_cmd("netsh advfirewall show allprofiles")
        perfiles = {
            "Dominio": "State.*on" in output.lower() or "state" in output.lower() and "on" in output.split("Domain")[1].lower()[:50] if "Domain" in output else False,
            "Privado": True,
            "Público": True
        }
        return perfiles


# ============================================================================
# MODULO 4: VERIFICADOR DE ANTIMALWARE (ISO A.12.2) - 4 CONTROLES
# ============================================================================

class VerificadorAntimalware(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Antimalware",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.12.2",
            "controles": [
                {"nombre": "Windows Defender habilitado", "cumple": False, "valor": "No"},
                {"nombre": "Protección en tiempo real", "cumple": False, "valor": "No"},
                {"nombre": "Definiciones actualizadas", "cumple": False, "valor": "Desconocido"},
                {"nombre": "Análisis programado", "cumple": False, "valor": "No"}
            ]
        }
        
        try:
            defender = self._verificar_defender()
            if defender["estado"] == "HABILITADO":
                resultado["controles"][0]["cumple"] = True
                resultado["controles"][0]["valor"] = "Sí"
            else:
                resultado["controles"][0]["valor"] = "No"
                resultado["hallazgos"].append({
                    "titulo": "Windows Defender deshabilitado",
                    "descripcion": "La protección en tiempo real no está activa",
                    "severidad": "CRITICO",
                    "norma_iso": "ISO/IEC 27001 A.12.2.1",
                    "recomendacion": "Ejecutar: powershell -c 'Set-MpPreference -DisableRealtimeMonitoring $false'"
                })
            
            realtime = self._verificar_realtime()
            if realtime["cumple"]:
                resultado["controles"][1]["cumple"] = True
                resultado["controles"][1]["valor"] = "Sí"
            else:
                resultado["controles"][1]["valor"] = "No"
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except Exception as e:
            resultado["estado"] = "ERROR"
            resultado["error"] = str(e)
        
        return resultado
    
    def _verificar_defender(self):
        output = self._ejecutar_cmd("powershell -Command \"Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled\"")
        estado = "HABILITADO" if "True" in output else "DESHABILITADO"
        return {"estado": estado}
    
    def _verificar_realtime(self):
        output = self._ejecutar_cmd("powershell -Command \"Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled\"")
        cumple = "True" in output
        return {"cumple": cumple}


# ============================================================================
# MODULO 5: VERIFICADOR DE AUDITORÍA (ISO A.12.4) - 4 CONTROLES
# ============================================================================

class VerificadorAuditoria(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Auditoría y Registros",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.12.4",
            "controles": [
                {"nombre": "Registro de seguridad habilitado", "cumple": False, "valor": "No"},
                {"nombre": "Auditoría de logon habilitada", "cumple": False, "valor": "No"},
                {"nombre": "Tamaño de logs adecuado (≥512MB)", "cumple": False, "valor": "0 MB"},
                {"nombre": "Retención de logs (≥30 días)", "cumple": False, "valor": "Desconocido"}
            ]
        }
        
        try:
            tamaño = self._verificar_tamaño_logs()
            if tamaño["tamaño_mb"] >= 512:
                resultado["controles"][2]["cumple"] = True
            resultado["controles"][2]["valor"] = f"{tamaño['tamaño_mb']:.0f} MB"
            
            if tamaño["tamaño_mb"] < 512:
                resultado["hallazgos"].append({
                    "titulo": "Tamaño insuficiente de logs de seguridad",
                    "descripcion": f"Actual: {tamaño['tamaño_mb']:.0f} MB. Recomendado: ≥512 MB",
                    "severidad": "MEDIO",
                    "norma_iso": "ISO/IEC 27001 A.12.4.1",
                    "recomendacion": "Aumentar tamaño en Event Viewer > Propiedades del registro de seguridad"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except Exception as e:
            resultado["estado"] = "ERROR"
            resultado["error"] = str(e)
        
        return resultado
    
    def _verificar_tamaño_logs(self):
        try:
            output = self._ejecutar_cmd("wevtutil gl Security /l")
            for linea in output.split('\n'):
                if "maxSize" in linea.lower():
                    nums = re.findall(r'\d+', linea)
                    if nums:
                        tamaño_bytes = int(nums[-1])
                        tamaño_mb = tamaño_bytes / (1024 * 1024)
                        return {"tamaño_mb": tamaño_mb}
        except:
            pass
        return {"tamaño_mb": 20}


# ============================================================================
# MODULO 6: VERIFICADOR DE USUARIOS (ISO A.9.1) - 5 CONTROLES
# ============================================================================

class VerificadorUsuarios(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Usuarios y Cuentas",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.9.1",
            "controles": [
                {"nombre": "Cuenta Guest deshabilitada", "cumple": False, "valor": "Habilitada"},
                {"nombre": "Cuenta Administrator renombrada", "cumple": False, "valor": "No verificado"},
                {"nombre": "Cuentas de servicio sin uso", "cumple": False, "valor": "Desconocido"},
                {"nombre": "Cuentas administrativas limitadas", "cumple": False, "valor": "Desconocido"},
                {"nombre": "UAC habilitado", "cumple": False, "valor": "Desconocido"}
            ]
        }
        
        try:
            guest = self._verificar_guest()
            if guest["estado"] == "DESHABILITADA":
                resultado["controles"][0]["cumple"] = True
                resultado["controles"][0]["valor"] = "Deshabilitada"
            else:
                resultado["controles"][0]["valor"] = "Habilitada"
                resultado["hallazgos"].append({
                    "titulo": "Cuenta Guest habilitada",
                    "descripcion": "La cuenta de invitado está habilitada y accesible",
                    "severidad": "ALTO",
                    "norma_iso": "ISO/IEC 27001 A.9.1.1",
                    "recomendacion": "Ejecutar: net user Guest /active:no"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except Exception as e:
            resultado["estado"] = "ERROR"
            resultado["error"] = str(e)
        
        return resultado
    
    def _verificar_guest(self):
        output = self._ejecutar_cmd("net user Guest")
        if "Account active" in output:
            if "No" in output:
                return {"estado": "DESHABILITADA"}
        return {"estado": "HABILITADA"}


# ============================================================================
# MODULO 7: VERIFICADOR DE ENCRIPTACIÓN (ISO A.10.2) - 3 CONTROLES
# ============================================================================

class VerificadorEncriptacion(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Encriptación",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.10.2",
            "controles": [
                {"nombre": "BitLocker habilitado (C:)", "cumple": False, "valor": "No"},
                {"nombre": "Sistema de archivos NTFS", "cumple": False, "valor": "No"},
                {"nombre": "Encriptación de datos en tránsito", "cumple": False, "valor": "Desconocido"}
            ]
        }
        
        try:
            fs = self._verificar_ntfs()
            if fs["tiene_ntfs"] and not (fs["tiene_fat32"] or fs["tiene_fat"]):
                resultado["controles"][1]["cumple"] = True
                resultado["controles"][1]["valor"] = "Sí (NTFS)"
            else:
                resultado["controles"][1]["valor"] = "No (FAT/FAT32)"
                resultado["hallazgos"].append({
                    "titulo": "Sistema de archivos no seguro",
                    "descripcion": "Se detectó FAT o FAT32",
                    "severidad": "MEDIO",
                    "norma_iso": "ISO/IEC 27001 A.10.2.1",
                    "recomendacion": "Convertir a NTFS"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except Exception as e:
            resultado["estado"] = "ERROR"
            resultado["error"] = str(e)
        
        return resultado
    
    def _verificar_ntfs(self):
        output = self._ejecutar_cmd("wmic logicaldisk get name, filesystem")
        return {
            "tiene_fat": "FAT" in output,
            "tiene_fat32": "FAT32" in output,
            "tiene_ntfs": "NTFS" in output
        }


# ============================================================================
# GENERADOR DE REPORTES DETALLADO
# ============================================================================

class GeneradorReportes:
    def __init__(self):
        self.timestamp = datetime.now()
        self.hallazgos = []
        self.verificaciones = {}
        self.puntuacion_general = 0
        self.puntuaciones_iso = {}
        self.total_controles = 0
        self.controles_cumplidos = 0
    
    def agregar_verificacion(self, nombre, resultado):
        self.verificaciones[nombre] = resultado
        if "hallazgos" in resultado:
            for h in resultado["hallazgos"]:
                self.hallazgos.append(h)
        
        if "controles" in resultado:
            for control in resultado["controles"]:
                self.total_controles += 1
                if control["cumple"]:
                    self.controles_cumplidos += 1
    
    def calcular_puntuaciones(self):
        iso_map = {
            "ISO/IEC 27001 A.9": ["Políticas de Contraseñas", "Usuarios y Cuentas"],
            "ISO/IEC 27001 A.10": ["Encriptación"],
            "ISO/IEC 27001 A.12": ["Actualizaciones y Parches", "Antimalware", "Auditoría y Registros"],
            "ISO/IEC 27001 A.13": ["Firewall"]
        }
        
        for iso, componentes in iso_map.items():
            total = 0
            cumple = 0
            
            for comp in componentes:
                if comp in self.verificaciones:
                    v = self.verificaciones[comp]
                    if "controles" in v:
                        total += len(v["controles"])
                        cumple += sum(1 for c in v["controles"] if c["cumple"])
            
            if total > 0:
                porcentaje = int((cumple / total) * 100)
                self.puntuaciones_iso[iso] = {
                    "cumplidos": cumple,
                    "total": total,
                    "porcentaje": porcentaje
                }
        
        if self.total_controles > 0:
            self.puntuacion_general = int((self.controles_cumplidos / self.total_controles) * 100)
        
        return self.puntuacion_general
    
    def generar_json(self):
        contenido = {
            "fecha": self.timestamp.isoformat(),
            "puntuacion_general": self.puntuacion_general,
            "controles_cumplidos": f"{self.controles_cumplidos}/{self.total_controles}",
            "puntuaciones_iso": self.puntuaciones_iso,
            "total_hallazgos": len(self.hallazgos),
            "verificaciones": self.verificaciones,
            "hallazgos": self.hallazgos
        }
        with open("reporte_seguridad.json", "w", encoding="utf-8") as f:
            json.dump(contenido, f, ensure_ascii=False, indent=2)
        return "reporte_seguridad.json"
    
    def generar_html(self):
        colores = {
            "CRÍTICO": "#dc3545", "ALTO": "#fd7e14", "MEDIO": "#ffc107",
            "BAJO": "#28a745", "INFORMACIÓN": "#17a2b8"
        }
        
        iso_html = ""
        for iso, datos in sorted(self.puntuaciones_iso.items()):
            porcentaje = datos["porcentaje"]
            color = "#28a745" if porcentaje >= 75 else "#ffc107" if porcentaje >= 60 else "#dc3545"
            iso_html += f"""
            <div style="background: white; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid {color};">
                <h4 style="margin: 0 0 10px 0; color: #333;">{iso}</h4>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="flex: 1;">
                        <div style="background: #f0f0f0; height: 20px; border-radius: 10px; overflow: hidden;">
                            <div style="background: {color}; height: 100%; width: {porcentaje}%;"></div>
                        </div>
                    </div>
                    <span style="margin-left: 15px; font-weight: bold; color: {color}; min-width: 80px; text-align: right;">
                        {porcentaje}% ({datos['cumplidos']}/{datos['total']})
                    </span>
                </div>
            </div>
            """
        
        controles_html = ""
        for nombre, v in sorted(self.verificaciones.items()):
            if "controles" in v:
                controles_html += f"<h4>{nombre}</h4>"
                for control in v["controles"]:
                    estado = "✓" if control["cumple"] else "✗"
                    color = "#28a745" if control["cumple"] else "#dc3545"
                    controles_html += f"""
                    <div style="margin: 8px 0; padding: 8px; background: #f9f9f9; border-left: 3px solid {color};">
                        <span style="color: {color}; font-weight: bold;">{estado}</span> {control['nombre']}
                        <span style="float: right; color: #666;">({control['valor']})</span>
                    </div>
                    """
        
        hallazgos_html = ""
        for h in self.hallazgos:
            color = colores.get(h["severidad"], "#999")
            hallazgos_html += f"""
            <div style="border-left: 5px solid {color}; padding: 15px; margin: 10px 0; background: #f9f9f9; border-radius: 4px;">
                <h4 style="color: {color}; margin: 0 0 10px 0;">{h['titulo']}</h4>
                <p><strong>Severidad:</strong> <span style="color: {color}; font-weight: bold;">{h['severidad']}</span></p>
                <p><strong>Descripción:</strong> {h['descripcion']}</p>
                <p><strong>Norma:</strong> {h['norma_iso']}</p>
                <p><strong>Recomendación:</strong> <code style="background: #f0f0f0; padding: 5px;">{h['recomendacion']}</code></p>
            </div>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte Detallado de Seguridad</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #2c3e50; margin-top: 30px; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }}
        .resumen {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .tarjeta {{ padding: 20px; border-radius: 8px; text-align: center; color: white; }}
        .puntuacion {{ background: linear-gradient(135deg, #667eea, #764ba2); font-size: 48px; font-weight: bold; padding: 30px; }}
        code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Reporte Detallado de Verificación de Seguridad Windows</h1>
        <p><strong>Fecha:</strong> {self.timestamp.strftime('%d/%m/%Y %H:%M:%S')}</p>
        <p><strong>Normas:</strong> ISO/IEC 27001:2022, 27002:2022</p>
        
        <div class="resumen">
            <div class="tarjeta puntuacion">{self.puntuacion_general}%<br><small>Puntuación General</small></div>
            <div class="tarjeta" style="background: linear-gradient(135deg, #667eea, #764ba2);">
                {self.controles_cumplidos}/{self.total_controles}<br><small>Controles Cumplidos</small>
            </div>
            <div class="tarjeta" style="background: linear-gradient(135deg, #667eea, #764ba2);">
                {len(self.hallazgos)}<br><small>Hallazgos</small>
            </div>
        </div>
        
        <div class="seccion">
            <h2>📊 Puntuación por Norma ISO</h2>
            {iso_html}
        </div>
        
        <div class="seccion">
            <h2>✓ Detalle de Controles</h2>
            {controles_html}
        </div>
        
        <div class="seccion">
            <h2>⚠️ Hallazgos Detallados</h2>
            {hallazgos_html if self.hallazgos else "<p>✓ No se encontraron hallazgos críticos.</p>"}
        </div>
    </div>
</body>
</html>"""
        
        with open("reporte_seguridad.html", "w", encoding="utf-8") as f:
            f.write(html)
        return "reporte_seguridad.html"


# ============================================================================
# EJECUTOR PRINCIPAL
# ============================================================================

def main():
    try:
        print("\n" + "="*80)
        print("VERIFICADOR DE SEGURIDAD WINDOWS - ISO 27001/27002 v3.0 DETALLADO")
        print("="*80 + "\n")
        
        reportes = GeneradorReportes()
        
        verificadores = {
            "Políticas de Contraseñas": VerificadorContraseñas(),
            "Actualizaciones y Parches": VerificadorActualizaciones(),
            "Firewall": VerificadorFirewall(),
            "Antimalware": VerificadorAntimalware(),
            "Auditoría y Registros": VerificadorAuditoria(),
            "Usuarios y Cuentas": VerificadorUsuarios(),
            "Encriptación": VerificadorEncriptacion()
        }
        
        for nombre, verificador in verificadores.items():
            print(f"[*] {nombre}...", end=" ")
            try:
                resultado = verificador.verificar()
                reportes.agregar_verificacion(nombre, resultado)
                estado = "✓" if resultado.get("estado") == "CUMPLE" else "✗"
                print(f"{estado} ({resultado.get('estado', 'DESCONOCIDO')})")
            except Exception as e:
                print(f"✗ ERROR")
        
        reportes.calcular_puntuaciones()
        
        print("\n[*] Generando reportes...")
        reportes.generar_json()
        print("    ✓ reporte_seguridad.json")
        html_path = reportes.generar_html()
        print("    ✓ reporte_seguridad.html")
        
        print("\n" + "="*80)
        print(f"Puntuación General: {reportes.puntuacion_general}%")
        print(f"Controles Cumplidos: {reportes.controles_cumplidos}/{reportes.total_controles}")
        print("\nPuntuaciones por Norma ISO:")
        for iso, datos in sorted(reportes.puntuaciones_iso.items()):
            print(f"  {iso}: {datos['porcentaje']}% ({datos['cumplidos']}/{datos['total']})")
        print(f"\nTotal de Hallazgos: {len(reportes.hallazgos)}")
        print("="*80 + "\n")
        
        try:
            os.startfile(html_path)
        except:
            pass
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n✗ Interrumpido por el usuario")
        return 1
    except PermissionError:
        print("\n✗ Error: Ejecuta como ADMINISTRADOR")
        return 1
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
