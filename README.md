python subrecon.py ejemplo.com

Con escaneo de puertos:
python subrecon.py ejemplo.com -p

Con wordlist propia y más hilos:
python subrecon.py ejemplo.com -w /ruta/wordlist.txt -t 50

[EJEMPLO COMPLETO SCAN]

python subrecon.py EJEMPLO.com -p -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

El programa al terminar crea un informe con todo. 
