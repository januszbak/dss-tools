
# dss-tools

<b>Graceful cluster shutdown and other commands to control DSS V7 remotely</b>
<br>Note: 
Please enable the CLI/API in GUI : 
Setup -> Administrator setting -> CLI/API Configuration
<br>

EXAMPLES:

<br>1. Graceful cluster stop and shutdown using default password and port

	dss-tools stop-cluster 192.168.0.220 192.168.0.221
<br>2. Graceful cluster stop and shutdown with non default password and port

	dss-tools --pswd password --port 22225 stop-cluster 192.168.0.220 192.168.0.221
<br>3. Start cluster with default password and port

	dss-tools start-cluster 192.168.0.220 192.168.0.221
<br>4. Run 100 times in loop graceful cluster stop-shutdown-start test

	dss-tools stop-start-test 192.168.0.220 192.168.0.221
<br>5. Shutdown three DSS servers using default port but non default password

	dss-tools --pswd password shutdown 192.168.0.220 192.168.0.221 192.168.0.222
<br>6. Reboot single DSS server

	dss-tools reboot 192.168.0.220
<br>7. Create vg00

	dss-tools create-vg00 192.168.0.220
<br>8. Set IP address on eth1 for nodes 192.168.0.220

	dss-tools set-ip 192.168.0.220 --new-ip eth1:10.10.10.220

#
#Create single exe file run:

	C:\Python27>Scripts\pyinstaller.exe --onefile dss-tools.py
#
And try it:

	C:\Python27>dist\dss-tools.exe -h
NOTE:
In case of error: "msvcr100.dll missing ...",
download and install: Microsoft Visual C++ 2010 Redistributable Package (x86) vcredist_x86.exe
