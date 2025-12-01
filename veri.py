#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VERIFICADOR DE SEGURIDAD WINDOWS - ISO 27001/27002
Versión 2.1 - Con Puntuación por ISO
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


# ============================================================================
# MODULO 1: VERIFICADOR DE CONTRASEÑAS (ISO A.9.2)
# ============================================================================

class VerificadorContraseñas(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Políticas de Contraseñas",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.9.2",
            "controles": [
                {"nombre": "Longitud mínima", "cumple": False},
                {"nombre": "Complejidad", "cumple": False},
                {"nombre": "Caducidad", "cumple": False}
            ]
        }
        
        try:
            if self._verificar_longitud_minima()["estado"] == "CUMPLE":
                resultado["controles"][0]["cumple"] = True
            else:
                resultado["hallazgos"].append({
                    "titulo": "Longitud mínima de contraseña insuficiente",
                    "descripcion": "Menor a 8 caracteres",
                    "severidad": "ALTO",
                    "norma_iso": "ISO/IEC 27001 A.9.2.1",
                    "recomendacion": "Establecer mínimo 12 caracteres"
                })
            
            if self._verificar_complejidad()["estado"] == "CUMPLE":
                resultado["controles"][1]["cumple"] = True
            else:
                resultado["hallazgos"].append({
                    "titulo": "Complejidad de contraseña no requerida",
                    "descripcion": "Las contraseñas no requieren mayúsculas, minúsculas, números y símbolos",
                    "severidad": "ALTO",
                    "norma_iso": "ISO/IEC 27001 A.9.2.1",
                    "recomendacion": "Habilitar requisito de contraseñas complejas"
                })
            
            if self._verificar_caducidad()["estado"] == "CUMPLE":
                resultado["controles"][2]["cumple"] = True
            else:
                resultado["hallazgos"].append({
                    "titulo": "Caducidad de contraseña no configurada",
                    "descripcion": "Sin política de cambio periódico",
                    "severidad": "MEDIO",
                    "norma_iso": "ISO/IEC 27001 A.9.2.3",
                    "recomendacion": "Establecer caducidad cada 90 días"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except:
            resultado["estado"] = "ERROR"
        
        return resultado
    
    def _ejecutar_cmd(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5)
        except:
            return ""
    
    def _verificar_longitud_minima(self):
        output = self._ejecutar_cmd("net accounts")
        nums = re.findall(r'\d+', output)
        if nums and int(nums[0]) >= 8:
            return {"estado": "CUMPLE"}
        return {"estado": "NO_CUMPLE"}
    
    def _verificar_complejidad(self):
        output = self._ejecutar_cmd("net accounts")
        return {"estado": "CUMPLE"} if "complexity" in output.lower() else {"estado": "NO_CUMPLE"}
    
    def _verificar_caducidad(self):
        output = self._ejecutar_cmd("net accounts")
        for linea in output.split('\n'):
            if "Maximum password age" in linea:
                nums = re.findall(r'\d+', linea)
                if nums:
                    val = int(nums[-1])
                    return {"estado": "CUMPLE"} if 0 < val <= 90 else {"estado": "NO_CUMPLE"}
        return {"estado": "NO_CUMPLE"}


# ============================================================================
# MODULO 2: VERIFICADOR DE ACTUALIZACIONES (ISO A.12.6)
# ============================================================================

class VerificadorActualizaciones(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Actualizaciones y Parches",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.12.6",
            "controles": [
                {"nombre": "Windows Update automático", "cumple": False}
            ]
        }
        
        try:
            if self._verificar_wu_automatico()["estado"] == "HABILITADO":
                resultado["controles"][0]["cumple"] = True
            else:
                resultado["hallazgos"].append({
                    "titulo": "Windows Update automático deshabilitado",
                    "descripcion": "Las actualizaciones automáticas no están habilitadas",
                    "severidad": "ALTO",
                    "norma_iso": "ISO/IEC 27001 A.12.6.1",
                    "recomendacion": "Habilitar actualizaciones automáticas"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except:
            resultado["estado"] = "ERROR"
        
        return resultado
    
    def _ejecutar_cmd(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5)
        except:
            return ""
    
    def _verificar_wu_automatico(self):
        output = self._ejecutar_cmd("powershell -Command \"Get-Service WuAuServ | Select-Object -ExpandProperty Status\"")
        return {"estado": "HABILITADO"} if "running" in output.lower() else {"estado": "DESHABILITADO"}


# ============================================================================
# MODULO 3: VERIFICADOR DE FIREWALL (ISO A.13.1)
# ============================================================================

class VerificadorFirewall(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Firewall",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.13.1",
            "controles": [
                {"nombre": "Firewall habilitado", "cumple": False}
            ]
        }
        
        try:
            if self._verificar_estado()["estado"] == "HABILITADO":
                resultado["controles"][0]["cumple"] = True
            else:
                resultado["hallazgos"].append({
                    "titulo": "Firewall deshabilitado",
                    "descripcion": "El firewall de Windows no está habilitado",
                    "severidad": "CRITICO",
                    "norma_iso": "ISO/IEC 27001 A.13.1.1",
                    "recomendacion": "Habilitar firewall de Windows"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except:
            resultado["estado"] = "ERROR"
        
        return resultado
    
    def _ejecutar_cmd(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5)
        except:
            return ""
    
    def _verificar_estado(self):
        output = self._ejecutar_cmd("netsh advfirewall show allprofiles state")
        return {"estado": "HABILITADO"} if "on" in output.lower() else {"estado": "DESHABILITADO"}


# ============================================================================
# MODULO 4: VERIFICADOR DE ANTIMALWARE (ISO A.12.2)
# ============================================================================

class VerificadorAntimalware(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Antimalware",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.12.2",
            "controles": [
                {"nombre": "Windows Defender habilitado", "cumple": False}
            ]
        }
        
        try:
            if self._verificar_defender()["estado"] == "HABILITADO":
                resultado["controles"][0]["cumple"] = True
            else:
                resultado["hallazgos"].append({
                    "titulo": "Windows Defender deshabilitado",
                    "descripcion": "Protección en tiempo real no está activa",
                    "severidad": "CRITICO",
                    "norma_iso": "ISO/IEC 27001 A.12.2.1",
                    "recomendacion": "Habilitar Windows Defender"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except:
            resultado["estado"] = "ERROR"
        
        return resultado
    
    def _ejecutar_cmd(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5)
        except:
            return ""
    
    def _verificar_defender(self):
        output = self._ejecutar_cmd("powershell -Command \"Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled\"")
        return {"estado": "HABILITADO"} if "True" in output else {"estado": "DESHABILITADO"}


# ============================================================================
# MODULO 5: VERIFICADOR DE AUDITORÍA (ISO A.12.4)
# ============================================================================

class VerificadorAuditoria(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Auditoría y Registros",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.12.4",
            "controles": [
                {"nombre": "Tamaño de logs adecuado", "cumple": False}
            ]
        }
        
        try:
            tamaño = self._verificar_tamaño_logs().get("tamaño_mb", 10)
            if tamaño >= 10:
                resultado["controles"][0]["cumple"] = True
            else:
                resultado["hallazgos"].append({
                    "titulo": "Registro de seguridad con tamaño insuficiente",
                    "descripcion": f"Tamaño máximo: {tamaño}MB (mínimo recomendado: 512MB)",
                    "severidad": "MEDIO",
                    "norma_iso": "ISO/IEC 27001 A.12.4.1",
                    "recomendacion": "Aumentar tamaño a 512MB"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except:
            resultado["estado"] = "ERROR"
        
        return resultado
    
    def _ejecutar_cmd(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5)
        except:
            return ""
    
    def _verificar_tamaño_logs(self):
        try:
            output = self._ejecutar_cmd("wevtutil gl Security /l")
            for linea in output.split('\n'):
                if "maxSize" in linea:
                    nums = re.findall(r'\d+', linea)
                    if nums:
                        return {"tamaño_mb": int(nums[-1]) / (1024 * 1024)}
        except:
            pass
        return {"tamaño_mb": 10}


# ============================================================================
# MODULO 6: VERIFICADOR DE USUARIOS (ISO A.9.1)
# ============================================================================

class VerificadorUsuarios(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Usuarios y Cuentas",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.9.1",
            "controles": [
                {"nombre": "Cuenta Guest deshabilitada", "cumple": False}
            ]
        }
        
        try:
            if self._verificar_guest()["estado"] == "DESHABILITADA":
                resultado["controles"][0]["cumple"] = True
            else:
                resultado["hallazgos"].append({
                    "titulo": "Cuenta Guest habilitada",
                    "descripcion": "Cuenta de invitado está habilitada",
                    "severidad": "ALTO",
                    "norma_iso": "ISO/IEC 27001 A.9.1.1",
                    "recomendacion": "Deshabilitar cuenta Guest"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except:
            resultado["estado"] = "ERROR"
        
        return resultado
    
    def _ejecutar_cmd(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5)
        except:
            return ""
    
    def _verificar_guest(self):
        output = self._ejecutar_cmd("net user Guest")
        return {"estado": "DESHABILITADA"} if "Account active" in output and "No" in output else {"estado": "HABILITADA"}


# ============================================================================
# MODULO 7: VERIFICADOR DE ENCRIPTACIÓN (ISO A.10.2)
# ============================================================================

class VerificadorEncriptacion(VerificadorBase):
    def verificar(self):
        resultado = {
            "componente": "Encriptación",
            "estado": "VERIFICADO",
            "hallazgos": [],
            "norma_referencia": "ISO/IEC 27001 A.10.2",
            "controles": [
                {"nombre": "Sistema de archivos NTFS", "cumple": False}
            ]
        }
        
        try:
            fs = self._verificar_ntfs()
            if fs["tiene_ntfs"] and not (fs["tiene_fat32"] or fs["tiene_fat"]):
                resultado["controles"][0]["cumple"] = True
            else:
                resultado["hallazgos"].append({
                    "titulo": "Sistema de archivos poco seguro",
                    "descripcion": "Se detectaron particiones con FAT32",
                    "severidad": "MEDIO",
                    "norma_iso": "ISO/IEC 27001 A.10.2.1",
                    "recomendacion": "Convertir particiones a NTFS"
                })
            
            resultado["estado"] = "NO_CUMPLE" if resultado["hallazgos"] else "CUMPLE"
        except:
            resultado["estado"] = "ERROR"
        
        return resultado
    
    def _ejecutar_cmd(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5)
        except:
            return ""
    
    def _verificar_ntfs(self):
        output = self._ejecutar_cmd("wmic logicaldisk get name, filesystem")
        return {
            "tiene_fat": "FAT" in output,
            "tiene_fat32": "FAT32" in output,
            "tiene_ntfs": "NTFS" in output
        }


# ============================================================================
# GENERADOR DE REPORTES CON PUNTUACIÓN POR ISO
# ============================================================================

class GeneradorReportes:
    def __init__(self):
        self.timestamp = datetime.now()
        self.hallazgos = []
        self.verificaciones = {}
        self.puntuacion_general = 0
        self.puntuaciones_iso = {}
    
    def agregar_verificacion(self, nombre, resultado):
        self.verificaciones[nombre] = resultado
        if "hallazgos" in resultado:
            for h in resultado["hallazgos"]:
                self.hallazgos.append(h)
    
    def calcular_puntuaciones(self):
        """Calcula puntuación general y por ISO"""
        # Mapeo de ISO a verificadores
        iso_map = {
            "ISO/IEC 27001 A.9": ["Políticas de Contraseñas", "Usuarios y Cuentas"],
            "ISO/IEC 27001 A.10": ["Encriptación"],
            "ISO/IEC 27001 A.12": ["Actualizaciones y Parches", "Antimalware", "Auditoría y Registros"],
            "ISO/IEC 27001 A.13": ["Firewall"]
        }
        
        # Calcular puntuación por ISO
        for iso, componentes in iso_map.items():
            total_controles = 0
            controles_cumplidos = 0
            
            for componente in componentes:
                if componente in self.verificaciones:
                    v = self.verificaciones[componente]
                    if "controles" in v:
                        total_controles += len(v["controles"])
                        controles_cumplidos += sum(1 for c in v["controles"] if c["cumple"])
            
            if total_controles > 0:
                porcentaje = int((controles_cumplidos / total_controles) * 100)
                self.puntuaciones_iso[iso] = {
                    "cumplidos": controles_cumplidos,
                    "total": total_controles,
                    "porcentaje": porcentaje
                }
        
        # Calcular puntuación general
        if self.verificaciones:
            total = len(self.verificaciones)
            cumple = sum(1 for v in self.verificaciones.values() if v.get("estado") == "CUMPLE")
            self.puntuacion_general = int((cumple / total) * 100)
        
        return self.puntuacion_general
    
    def generar_json(self):
        contenido = {
            "fecha": self.timestamp.isoformat(),
            "puntuacion_general": self.puntuacion_general,
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
        
        # HTML para puntuaciones por ISO
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
                            <div style="background: {color}; height: 100%; width: {porcentaje}%; transition: width 0.3s;"></div>
                        </div>
                    </div>
                    <span style="margin-left: 15px; font-weight: bold; color: {color}; min-width: 60px; text-align: right;">
                        {porcentaje}% ({datos['cumplidos']}/{datos['total']})
                    </span>
                </div>
            </div>
            """
        
        hallazgos_html = ""
        for h in self.hallazgos:
            color = colores.get(h["severidad"], "#999")
            hallazgos_html += f"""
            <div style="border-left: 5px solid {color}; padding: 15px; margin: 10px 0; background: #f9f9f9; border-radius: 4px;">
                <h4 style="color: {color}; margin: 0 0 10px 0;">{h['titulo']}</h4>
                <p><strong>Severidad:</strong> {h['severidad']}</p>
                <p><strong>Descripción:</strong> {h['descripcion']}</p>
                <p><strong>Norma:</strong> {h['norma_iso']}</p>
                <p><strong>Recomendación:</strong> {h['recomendacion']}</p>
            </div>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #2c3e50; margin-top: 30px; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }}
        .resumen {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .tarjeta {{ padding: 20px; border-radius: 8px; text-align: center; color: white; }}
        .puntuacion {{ background: linear-gradient(135deg, #667eea, #764ba2); font-size: 48px; font-weight: bold; padding: 30px; }}
        .seccion {{ margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Reporte de Verificación de Seguridad Windows</h1>
        <p><strong>Fecha:</strong> {self.timestamp.strftime('%d/%m/%Y %H:%M:%S')}</p>
        <p><strong>Normas:</strong> ISO/IEC 27001:2022, 27002:2022</p>
        
        <div class="resumen">
            <div class="tarjeta puntuacion">{self.puntuacion_general}%<br><small>Puntuación General</small></div>
            <div class="tarjeta" style="background: linear-gradient(135deg, #667eea, #764ba2);">
                {len(self.hallazgos)}<br><small>Hallazgos</small>
            </div>
        </div>
        
        <div class="seccion">
            <h2>📊 Puntuación por Norma ISO</h2>
            {iso_html}
        </div>
        
        <div class="seccion">
            <h2>🔍 Detalle de Hallazgos</h2>
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
        print("VERIFICADOR DE SEGURIDAD WINDOWS - ISO 27001/27002")
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
            print(f"[*] Verificando {nombre}...", end=" ")
            try:
                resultado = verificador.verificar()
                reportes.agregar_verificacion(nombre, resultado)
                estado = "✓" if resultado.get("estado") == "CUMPLE" else "✗"
                print(estado)
            except Exception as e:
                print(f"✗ ({str(e)})")
        
        reportes.calcular_puntuaciones()
        
        print("\n[*] Generando reportes...")
        reportes.generar_json()
        print("    ✓ reporte_seguridad.json")
        html_path = reportes.generar_html()
        print("    ✓ reporte_seguridad.html")
        
        print("\n" + "="*80)
        print(f"Puntuación General: {reportes.puntuacion_general}%")
        print("\nPuntuaciones por ISO:")
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
