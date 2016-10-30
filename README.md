# dss-tools
Graceful cluster shutdown and other commands to control DSS V7 remotely

EXAMPLES:
 1. Graceful cluster stop and shutdown using default password and port
      dss-tools stop-cluster 192.168.0.220 192.168.0.221
 2. Graceful cluster stop and shutdown with non default password and port
      dss-tools --pswd password --port 22225 stop-cluster 192.168.0.220 192.168.0.221
 3. Start cluster with default password and port
      dss-tools start-cluster 192.168.0.220 192.168.0.221
 4. Run 100 times in loop graceful cluster stop-shutdown-start test
      dss-tools stop-start-test 192.168.0.220 192.168.0.221
 5. Shutdown three DSS servers using default port but non default password
      dss-tools --pswd password shutdown 192.168.0.220 192.168.0.221 192.168.0.222
 6. Reboot single DSS server
      dss-tools reboot 192.168.0.220
 7. Create vg00
      dss-tools create-vg00 192.168.0.220
 8. Set IP address on eth1 for nodes 192.168.0.220
      dss-tools set-ip 192.168.0.220 --new-ip eth1:10.10.10.220
      

In order to create single exe file run:
    C:\Python27>Scripts\pyinstaller.exe --onefile dss-tools.py
And try it:
    C:\Python27>dist\dss-tools.exe -h

