"""
DATE            VERSION       MODIFIED BY             REMARKS
24-Oct-2018     0.1           Aniruddha               Created Module for OBJDUMP
25-Oct-2018     0.2           Aniruddha               Created Modules for APKSIGNER
26-Oct-2018     0.3           Aniruddha               Created Modules for Source Code Searching
29-Oct-2018     0.4           Aniruddha               Modularized the code for readability
05-Dec-2018     0.5           Abhishek                Included XML files in hard code search
10-Jan-2019     0.6           Aniruddha               Replaced "echo to log file" with "Python API"
11-Jan-2019     0.7           Aniruddha               Added MD5 "Identification Info" and timing info
21-Jan-2019     0.8           Aniruddha               Added Source code "Identification Info"
24-Jan-2019     0.9           Aniruddha               Added section v5.1 for http and https
20-Feb-2019     1.0           Aniruddha               Removed grep. Added python API.
21-Feb-2019     1.1           Aniruddha               Modified hardcode search. Removed v0.5 sections.
25-Feb-2019     1.2           Aniruddha               Modified APKSIGNER code
04-Mar-2019     1.3           Aniruddha               Added command line options
07-Mar-2019     1.4           Aniruddha               Added exception handlers for file opening
11-Nov-2019     1.5           Aniruddha               Search for Serializable / Parcelable optimized
13-Nov-2019     1.6           Aniruddha               Optimized onReceive search
27-Nov-2019     1.7           Aniruddha               Removed some os.command calls
27-Nov-2019     1.8           Aniruddha               Log the identification hashes to xlsx
27-Nov-2019     1.9           Aniruddha               Autodetect linux and add basic GUI

"""

import analyze_apk
import datetime
import globals
import os
import analyze_code
import shutil
import getopt
import sys
#**************************************************************************
#Analyze source code and APK
#**************************************************************************
def analyze_target():
    #V2.1	Verify that system credential storage facilities are used appropriately
    analyze_code.search_storage()
    #V2.2 Verify that no sensitive data is written to application logs.
    analyze_code.search_logging()
    #V2.4 Verify that the keyboard cache is disabled on text inputs
    analyze_code.search_keyboard_cache()
    #V2.5 Verify that the clipboard is deactivated on text fields
    analyze_code.search_clipboard()
    #V2.7 Verify that no sensitive data exposed through the user interface
    analyze_code.search_masking()
    #V3.1	Verify that the app does not rely on symmetric cryptography with hardcoded keys
    analyze_code.search_hardcode_keys()
    #V3.3 Verify that the app uses proven implementations of cryptographic primitives.
    analyze_code.search_old_algos()
    #V3.6	Verify that all random values are generated using secure random
    analyze_code.search_random()
    #V4.1 Verify that if the app provides users an acceptable form of authentication
    analyze_code.search_authentication()
    #V5.1 Verify that data is encrypted on the network using TLS
    analyze_code.search_transport()
    #V5.3	Verify that the app verifies the X.509 certificate of the remote endpoint
    analyze_code.search_x509_validation()
    #V6.2	Verify that all inputs from external sources and the user are validated
    analyze_code.search_ipc_input()
    #V6.4	Verify that the app does not export sensitive functionality through IPC
    analyze_code.search_ipc_output()
    #V6.5 Verify that JavaScript is disabled in WebViews unless explicitly required.
    analyze_code.search_setJavaScriptEnabled()
    #V6.6 Verify that WebViews are configured to allow only the minimum set of protocol
    analyze_code.search_webview_config()
    #V6.7 If the native methods of the app are exposed to a WebView,
    analyze_code.search_addjavascriptinterface()
    #V6.8 Verify that object serialization, if any, is implemented using safe serialization APIs.
    analyze_code.search_serialization()
    if globals.gv_linux == True:
        #V7.1	Verify that the app is signed and provisioned with valid certificate.
        analyze_apk.apksigner()
        #V7.3	Verify that debugging symbols have been removed from native binaries.
        analyze_apk.objdump()
    #V7.4	Verify that debugging code has been removed, and the app does not log
    analyze_code.search_debugging_code()
    #V7.9 Free security features offered by the toolchain, such as byte-code minification
    analyze_code.search_gradle()
#**************************************************************************
#Parse arguments
#**************************************************************************
def parse_arguments(p_argv):
    # Running on Linux system
    globals.gv_linux = "Linux" in os.uname()

    try:
        # Specify the options
        opts, args = getopt.getopt(p_argv, 'a:c:h', ['apk=', 'code=','help'])
    except getopt.GetoptError:
        # Help text for exception cases
        print("android_script --help")
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print("script version 1.8 dated 27-Nov-2019")
            # Help text
            print("\nUsage:\nandroid_script --apk <path to apk> --code <path to source folder>")
            sys.exit(2)
        elif opt in ('-a', '--apk'):
            # Path to Source code
            globals.gv_path_to_apk_file = arg
        elif opt in ('-c', '--code'):
            # Path to APK
            globals.gv_path_to_code_folder = arg
    # Base path
    globals.gv_path_to_base = os.path.commonprefix([globals.gv_path_to_apk_file, globals.gv_path_to_code_folder])
    # Path to apksigner
    globals.gv_path_to_apksigner = "/root/Android/Sdk/build-tools/28.0.3/apksigner"

#**************************************************************************
#Main function of the Android Script
#**************************************************************************
def main(p_argv):
    #Parse arguments
    parse_arguments(p_argv)
    #Check if directory of logs exists
    if os.path.exists("logs"):
        #Delete previous log directory and its contents
        shutil.rmtree("logs")
    #Create a blank logs directory
    os.makedirs("logs")
    #Get all Identification info from source code and APK
    globals.identify_target()
    #Analyze source and apk
    analyze_target()
    print("Total time taken: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#Call to main function
if __name__== "__main__":
    main(sys.argv[1:])
