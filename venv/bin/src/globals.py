import datetime
import hashlib
import os
import analyze_code
import analyze_apk
import getopt

#Global variables
gv_path_to_base = None
gv_path_to_apk_file = None
gv_path_to_code_folder = None
gv_path_to_error_file = "logs/log_error.txt"
gv_linux = False
gv_time_start = datetime.datetime.now()

#**************************************************************************
#Writes text (in append mode) to a given file
#**************************************************************************
def write_to_file(p_text_to_write, p_file_to_write):
    #File pointer initialized in append mode
    lv_file_pointer = open(p_file_to_write,"a+")
    #Writes text to the file
    lv_file_pointer.write(p_text_to_write)
    #Closes the file
    lv_file_pointer.close()

#**************************************************************************
#Calculates MD5 of any given file
#**************************************************************************
def calculate_hash(p_file_to_identify, p_file_to_write):
    #File pointer initialized in append mode
    try:
        lv_file_pointer = open(p_file_to_identify,"rb")
        #Calculate MD5
        lv_md5 =  hashlib.md5(lv_file_pointer.read()).hexdigest()
        # Create relative path
        lv_filename = os.path.relpath(p_file_to_identify, gv_path_to_base)
        #Write to file
        write_to_file(lv_md5 + " " + lv_filename + "\n", p_file_to_write)
        #Closes the file
        lv_file_pointer.close()
    except:
        lv_filename = os.path.relpath(p_file_to_identify, gv_path_to_base)
        write_to_file("Error hashing file: " + lv_filename + "\n", gv_path_to_error_file)

#**************************************************************************
#Calculates MD5 of source code and APK
#**************************************************************************
def identify_target():
    write_to_file("START OF: SOURCE CODE Identification Info\n", "logs/log_v0.0.txt")
    # Log all MD5 info of APK
    write_to_file("\nResults for: MD5 and APK\n", "logs/log_v0.0.txt")
    calculate_hash(gv_path_to_apk_file , "logs/log_v0.0.txt")

    # Log all MD5 info of Source code files
    write_to_file("\nResults for: MD5 and Source Code\n", "logs/log_v0.0.txt")
    for root, dirs, files in os.walk(gv_path_to_code_folder):
            for file in files:
                  calculate_hash(os.path.join(root, file), "logs/log_v0.0.txt")
    print("Completed V0.0 by: " + str( (datetime.datetime.now() - gv_time_start ).total_seconds() ) + " seconds")
