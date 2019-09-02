import os
import zipfile
import globals
import hashlib
import datetime
import subprocess
import sys
#**************************************************************************
#OWASP MASVS v1.0 point 7.1
#Cheat Sheet:
#Execute apksigner verify -verbose <apk>
#Details:
#Verify that debugging code has been removed, and the app does not log
# verbose errors or debugging messages.
#**************************************************************************
def apksigner():
    globals.write_to_file("START OF: Execution log for V7.1\n", "logs/log_v7.1.txt")
    #Create the command
    command = globals.gv_path_to_apksigner + " verify --verbose " + "\"" + globals.gv_path_to_apk_file + "\""
    #Collect result
    result = subprocess.check_output(command, shell=True).decode(sys.stdout.encoding)
    #command = command + " >> logs/log_v7.1.txt"
    #os.system(command)
    #write output to file
    globals.write_to_file(result, "logs/log_v7.1.txt")
    globals.write_to_file("\nEND OF: Execution log for V7.1\n", "logs/log_v7.1.txt")
    print("Completed V7.1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 7.3
#Cheat Sheet:
#Unzip apk, list all .so files, Execute objdump -h <apk> | grep debug
#Details:
#Verify that debugging code has been removed, and the app does not log
# verbose errors or debugging messages.
#**************************************************************************
def objdump():

    lv_directory_to_extract_to = "temporary"
	#Extract APK
    zip_ref = zipfile.ZipFile(globals.gv_path_to_apk_file, 'r')
    zip_ref.extractall(lv_directory_to_extract_to)
    zip_ref.close()

    #Find all shared objects files
    globals.write_to_file("START OF: Execution log for V7.3\n", "logs/log_v7.3.txt")
    globals.write_to_file("\nFollowing Shared Objects were found:\n", "logs/log_v7.3.txt")

    for root, dirs, files in os.walk(lv_directory_to_extract_to):
        for file in files:
            if file.endswith(".so"):
              os.system("echo " + os.path.relpath(os.path.join(root, file), lv_directory_to_extract_to ) + " >> logs/log_v7.3.txt")

    #Execute 'objdump' command on shared objects
    os.system( "echo '\nFollowing debug symbols were found:' >> logs/log_v7.3.txt")
    for root, dirs, files in os.walk(lv_directory_to_extract_to):
        for file in files:
            if file.endswith(".so"):
                 command = "objdump -h " + os.path.join(root, file)  + " | grep debug | echo >> logs/log_v7.3.txt"
                 os.system(command)

    os.system("rm -r " + lv_directory_to_extract_to )
    #os.system( "echo '\nEND OF: Execution log for V7.3\n' >> logs/log_v7.3.txt")
    globals.write_to_file("\nEND OF: Execution log for V7.3\n", "logs/log_v7.3.txt")
    print("Completed V7.3 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


