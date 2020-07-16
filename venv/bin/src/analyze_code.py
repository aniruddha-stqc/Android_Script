import os
import globals
import datetime
import re
#**************************************************************************
#Hard coding search case insensitively in all files
#**************************************************************************
def search_hardcode(text_to_find, file_to_write):
    globals.write_to_file("\nResults for: " + text_to_find + "\n", file_to_write)
    for root, dirs, files in os.walk(globals.gv_path_to_code_folder):
        for file in files:
            if file.endswith(".java") or file.endswith(".xml") or file.endswith(".gradle"):
                try:
                    lv_searchfile = open(os.path.join(root, file), 'r')
                    # read the contents of the file
                    with lv_searchfile as searchfile:
                    #read one line at a time
                        for line_num, line_text in enumerate(searchfile):
                            #Case insensitive search for the text
                            if re.search(text_to_find, line_text, re.IGNORECASE):
                                #Create relative path
                                lv_filename = os.path.relpath ( os.path.join(root, file), globals.gv_path_to_base)
                                #Write results to the log
                                globals.write_to_file( lv_filename + ":" + str(line_num) + "  " + line_text, file_to_write)
                except:
                    lv_filename = os.path.relpath(os.path.join(root, file), globals.gv_path_to_base)
                    globals.write_to_file("Error analyzing file: " + lv_filename + "\n", globals.gv_path_to_error_file)

#**************************************************************************
#Generic Search Function to find strings in files as per following:
#Print the file name, line number, and line for each match.
#**************************************************************************
def search_generic(file_type_to_search, text_to_find, file_to_write):
    globals.write_to_file("\nResults for: " + text_to_find + "\n", file_to_write)
    for root, dirs, files in os.walk(globals.gv_path_to_code_folder):
        for file in files:
            #Search in the JAVA/xml/gradle files
            if file.endswith(file_type_to_search):
                try:
                    lv_searchfile = open(os.path.join(root, file), 'r')
                    #read the contents of the file
                    with lv_searchfile as searchfile:
                        #read one line at a time
                        for line_num, line_text in enumerate(searchfile):
                            #Case insensitive search for the text
                            if re.search(text_to_find, line_text):
                                #Create relative path
                                lv_filename = os.path.relpath ( os.path.join(root, file), globals.gv_path_to_base)
                                #Write results to the log
                                globals.write_to_file( lv_filename + ":" + str(line_num) + "  " + line_text, file_to_write)
                except:
                    lv_filename = os.path.relpath(os.path.join(root, file), globals.gv_path_to_base)
                    globals.write_to_file("Error analyzing file: " + lv_filename + "\n", globals.gv_path_to_error_file)
#**************************************************************************
#OWASP MASVS v1.0 point 2.1
#Cheat Sheet:
#Search for '"SharedPreferences ", "MODE_WORLD_", "Realm ",
# "FileOutputStream ", "getExternalFilesDir", "getExternalStorageDirectory",
# "getWritableDatabase", "getReadableDatabase", "getCacheDir",
# "getExternalCacheDirs", "KeyStore",
#Details:
#Verify that system credential storage facilities are used appropriately to
# store sensitive data, such as PII, user credentials or cryptographic keys.
#**************************************************************************
def search_storage():
    globals.write_to_file("START OF: Execution log for V2.1\n", "logs/log_v2.1.txt")
    search_generic(".java","SharedPreferences ", 'logs/log_v2.1.txt')
    search_generic(".java","getSharedPreferences", 'logs/log_v2.1.txt')
    search_generic(".java","MODE_WORLD_READABLE", 'logs/log_v2.1.txt')
    search_generic(".java","MODE_WORLD_WRITABLE", 'logs/log_v2.1.txt')
    search_generic(".java","SQLiteDatabase ", 'logs/log_v2.1.txt')
    search_generic(".java","Realm ", 'logs/log_v2.1.txt')
    search_generic(".java","FileOutputStream ", 'logs/log_v2.1.txt')
    search_generic(".java","getExternalFilesDir", 'logs/log_v2.1.txt')
    search_generic(".java","getExternalStorageDirectory", 'logs/log_v2.1.txt')
    search_generic(".java","getWritableDatabase", 'logs/log_v2.1.txt')
    search_generic(".java","getReadableDatabase", 'logs/log_v2.1.txt')
    search_generic(".java","getCacheDir", 'logs/log_v2.1.txt')
    search_generic(".java","getExternalCacheDirs", 'logs/log_v2.1.txt')
    search_generic(".java","KeyStore", 'logs/log_v2.1.txt')
    globals.write_to_file("\nEND OF: Execution log for V2.1\n", "logs/log_v2.1.txt")
    print("Completed V2.1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 2.2
#Cheat Sheet:
#Search for 'Log.d\|Log.e\|Log.i\|Log.v\|Log.w\|Log.wtf'
#Details:
#Verify that no sensitive data is written to application logs.
#**************************************************************************
def search_logging():
    globals.write_to_file("START OF: Execution log for V2.2\n", "logs/log_v2.2.txt")
    search_generic(".java","Log.d", 'logs/log_v2.2.txt')
    search_generic(".java","Log.e", 'logs/log_v2.2.txt')
    search_generic(".java","Log.i", 'logs/log_v2.2.txt')
    search_generic(".java","Log.v", 'logs/log_v2.2.txt')
    search_generic(".java","Log.w", 'logs/log_v2.2.txt')
    search_generic(".java","Log.wtf", 'logs/log_v2.2.txt')
    search_generic(".java","android.util.Log", 'logs/log_v2.2.txt')
    search_generic(".java","Logger", 'logs/log_v2.2.txt')
    search_generic(".java","logfile", 'logs/log_v2.2.txt')
    search_generic(".java","logging", 'logs/log_v2.2.txt')
    search_generic(".java","logs", 'logs/log_v2.2.txt')
    search_generic(".java","System.out.print", 'logs/log_v2.2.txt')
    search_generic(".java","System.out.println", 'logs/log_v2.2.txt')
    search_generic(".java","System.err.print", 'logs/log_v2.2.txt')
    globals.write_to_file("\nEND OF: Execution log for V2.2\n", "logs/log_v2.2.txt")
    print("Completed V2.2 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")
#**************************************************************************
#OWASP MASVS v1.0 point 2.4
#Cheat Sheet:
#Search for "textPassword", "textNoSuggestions" in xml files
#Details:
#Verify that the keyboard cache is disabled on text inputs that process
# sensitive data.
#**************************************************************************
def search_keyboard_cache():
    globals.write_to_file("START OF: Execution log for V2.4\n", "logs/log_v2.4.txt")
    globals.write_to_file("START OF: Execution log for V2.2\n", "logs/log_v2.2.txt")
    os.system( "echo '\nIMPORTANT: Best tested on Real Device\n' >> logs/log_v2.4.txt")
    search_generic(".xml","textPassword", 'logs/log_v2.5.txt')
    search_generic(".xml","textNoSuggestions", 'logs/log_v2.4.txt')
    globals.write_to_file("\nEND OF: Execution log for V2.4\n", "logs/log_v2.4.txt")
    print("Completed V2.4 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 2.5
#Cheat Sheet:
#Search for "textPassword", "longClickable" in xml files
#Details:
#Verify that the clipboard is deactivated on text fields that may contain
#sensitive data.
#**************************************************************************
def search_clipboard():
    globals.write_to_file("START OF: Execution log for V2.5\n", "logs/log_v2.5.txt")
    globals.write_to_file("START OF: Execution log for V2.2\n", "logs/log_v2.2.txt")
    os.system( "echo '\nIMPORTANT: Best tested on Real Device\n' >> logs/log_v2.5.txt")
    search_generic(".xml","textPassword", 'logs/log_v2.5.txt')
    search_generic(".xml","longClickable", 'logs/log_v2.5.txt')
    globals.write_to_file("\nEND OF: Execution log for V2.5\n", "logs/log_v2.5.txt")
    print("Completed V2.5 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 2.7
#Cheat Sheet:
#Search for "textPassword" in xml files
#Details:
#Verify that no sensitive data, such as passwords and credit card
#numbers, is exposed through the user interface or leaks to screenshots.
#**************************************************************************
def search_masking():
    globals.write_to_file("START OF: Execution log for V2.7\n", "logs/log_v2.7.txt")
    globals.write_to_file("START OF: Execution log for V2.2\n", "logs/log_v2.2.txt")
    os.system( "echo '\nIMPORTANT: Best tested on Real Device\n' >> logs/log_v2.7.txt")
    search_generic(".xml","textPassword", 'logs/log_v2.7.txt')
    globals.write_to_file("\nEND OF: Execution log for V2.7\n", "logs/log_v2.7.txt")
    print("Completed V2.7 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 3.1
#Cheat Sheet:
#Search for "secret", "key", "password", "passphrase", "SecretKeySpec",
# "AES", "IvParameterSpec", "cipher.init",
#Details:
#Verify that the app does not rely on symmetric cryptography with hardcoded
# keys as a sole method of encryption.
#**************************************************************************
def search_hardcode_keys():
    globals.write_to_file("START OF: Execution log for V3.1\n", "logs/log_v3.1.txt")
    search_hardcode("confidential", 'logs/log_v3.1.txt')
    search_hardcode("key", 'logs/log_v3.1.txt')
    search_hardcode("password", 'logs/log_v3.1.txt')
    search_hardcode("passphrase", 'logs/log_v3.1.txt')
    search_hardcode("Token", 'logs/log_v3.1.txt')
    search_hardcode("final", 'logs/log_v3.1.txt')
    search_hardcode("enum", 'logs/log_v3.1.txt')
    search_hardcode("AUTHTOKEN", 'logs/log_v3.1.txt')
    search_hardcode("SecretKeySpec", 'logs/log_v3.1.txt')
    search_hardcode("AES", 'logs/log_v3.1.txt')
    search_hardcode("IvParameterSpec", 'logs/log_v3.1.txt')
    search_hardcode("cipher.init", 'logs/log_v3.1.txt')
    globals.write_to_file("\nEND OF: Execution log for V3.1\n", "logs/log_v3.1.txt")
    print("Completed V3.1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 3.2
#Cheat Sheet:
#Search for 
#Details:
#
#**************************************************************************
def search_algos():
    globals.write_to_file("START OF: Execution log for V3.2\n", "logs/log_v3.2.txt")
    search_generic(".java","KeyPairGeneratorSpec", 'logs/log_v3.2.txt')
    search_generic(".java","KeyGenParameterSpec", 'logs/log_v3.2.txt')
    search_generic(".java","ENCRYPT_MODE", 'logs/log_v3.2.txt')
    search_generic(".java","DECRYPT_MODE", 'logs/log_v3.2.txt')
    search_generic(".java","Cipher.getInstance", 'logs/log_v3.2.txt')
    search_generic(".java","getBytes", 'logs/log_v3.2.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V3.2\n", "logs/log_v3.2.txt")
    print("Completed V3.2 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 3.3
#Cheat Sheet:
#Search for "DES", "3DES", "RC2", "RC4", "BLOWFISH", "MD4", "MD5", "SHA",
#Details:
#Verify that the app uses proven implementations of cryptographic primitives.
#**************************************************************************
def search_old_algos():
    globals.write_to_file("START OF: Execution log for V3.3\n", "logs/log_v3.3.txt")
    search_generic(".java","DES", 'logs/log_v3.3.txt')
    search_generic(".java","3DES", 'logs/log_v3.3.txt')
    search_generic(".java","RC2", 'logs/log_v3.3.txt')
    search_generic(".java","RC4", 'logs/log_v3.3.txt')
    search_generic(".java","BLOWFISH", 'logs/log_v3.3.txt')
    search_generic(".java","MD4", 'logs/log_v3.3.txt')
    search_generic(".java","MD5", 'logs/log_v3.3.txt')
    search_generic(".java","SHA", 'logs/log_v3.3.txt')
    search_generic(".java","SHA1", 'logs/log_v3.3.txt')
    search_generic(".java","hashCode", 'logs/log_v3.3.txt')
    globals.write_to_file("\nEND OF: Execution log for V3.3\n", "logs/log_v3.3.txt")
    print("Completed V3.3 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 3.6
#Cheat Sheet:
#Search for 'Random('
#Details:
#Verify that all random values are generated using a sufficiently secure
# random number generator.
#**************************************************************************
def search_random():
    globals.write_to_file("START OF: Execution log for V3.6\n", "logs/log_v3.6.txt")
    search_generic(".java","Random", 'logs/log_v3.6.txt')
    globals.write_to_file("\nEND OF: Execution log for V3.6\n", "logs/log_v3.6.txt")
    print("Completed V3.6 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 4.1
#Cheat Sheet:
#Search for "OTP",
#Details:
#Verify that if the app provides users with access to a remote service, an
#acceptable form of authentication such as username/password authentication
#  is performed at the remote endpoint..
#**************************************************************************
def search_authentication():
    globals.write_to_file("START OF: Execution log for V4.1\n", "logs/log_v4.1.txt")
    search_generic(".java","OTP", 'logs/log_v4.1.txt')
    globals.write_to_file("\nEND OF: Execution log for V4.1\n", "logs/log_v4.1.txt")
    print("Completed V4.1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 5.1
#Cheat Sheet:
#Search for "http://", "https://", ""
#Details:
#Verify that data is encrypted on the network using TLS. The secure channel
# is used consistently throughout the app.
#**************************************************************************
def search_transport():
    globals.write_to_file("START OF: Execution log for V5.1\n", "logs/log_v5.1.txt")
    search_hardcode("http:", 'logs/log_v5.1.txt')
    search_hardcode("https:", 'logs/log_v5.1.txt')
    search_hardcode("ftp:", 'logs/log_v5.1.txt')
    search_hardcode("sftp:", 'logs/log_v5.1.txt')
    globals.write_to_file("\nEND OF: Execution log for V5.1\n", "logs/log_v5.1.txt")
    print("Completed V5.1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")
#**************************************************************************
#OWASP MASVS v1.0 point 5.3
#Cheat Sheet:
#Search for "SSLSocketFactory", "X509TrustManager", "getAcceptedIssuers",
#"checkClientTrusted", "checkServerTrusted", "onReceivedSslError",
# "handler.proceed", "HostnameVerifier", ALLOW_ALL_HOSTNAME_VERIFIER",
#Details:
#Verify that the app verifies the X.509 certificate of the remote endpoint
# when the secure channel is established. Only certificates signed  by a
# valid CA are accepted.
#**************************************************************************
def search_x509_validation():
    globals.write_to_file("START OF: Execution log for V5.3\n", "logs/log_v5.3.txt")
    search_generic(".java","SSLSocketFactory", 'logs/log_v5.3.txt')
    search_generic(".java","X509TrustManager", 'logs/log_v5.3.txt')
    search_generic(".java","getAcceptedIssuers", 'logs/log_v5.3.txt')
    search_generic(".java","checkClientTrusted", 'logs/log_v5.3.txt')
    search_generic(".java","checkServerTrusted", 'logs/log_v5.3.txt')
    search_generic(".java","onReceivedSslError", 'logs/log_v5.3.txt')
    search_generic(".java","handler.proceed", 'logs/log_v5.3.txt')
    search_generic(".java","HostnameVerifier", 'logs/log_v5.3.txt')
    search_generic(".java","ALLOW_ALL_HOSTNAME_VERIFIER", 'logs/log_v5.3.txt')
    globals.write_to_file("\nEND OF: Execution log for V5.3\n", "logs/log_v5.3.txt")
    print("Completed V5.3 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.2
#Cheat Sheet:
#Search for 'GPS', "PendingIntent"
#Details:
#Verify that all inputs from external sources and the user are validated
# and if necessary sanitized. This includes data received via the UI, IPC
# mechanisms such as intents, custom URLs, and network sources.
#**************************************************************************
def search_ipc_input():
    globals.write_to_file("START OF: Execution log for V6.2\n", "logs/log_v6.2.txt")
    search_generic(".java"," onReceive(", 'logs/log_v6.2.txt')
    search_generic(".java","registerReceiver", 'logs/log_v6.2.txt')
    search_generic(".java","GPS", 'logs/log_v6.2.txt')
    search_generic(".java","PendingIntent", 'logs/log_v6.2.txt')
    globals.write_to_file("\nEND OF: Execution log for V6.2\n", "logs/log_v6.2.txt")
    print("Completed V6.2 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.4
#Cheat Sheet:
#Search for 'Notification', "NotificationManager", "sendBroadcast",
# "sendOrderedBroadcast", "sendStickyBroadcast", "sendStickyOrderedBroadcast",
#Details:
#Verify that the app does not export sensitive functionality through IPC
# facilities, unless these mechanisms are properly protected.
#**************************************************************************
def search_ipc_output():
    globals.write_to_file("START OF: Execution log for V6.4\n", "logs/log_v6.4.txt")
    search_generic(".java","Notification", 'logs/log_v6.4.txt')
    search_generic(".java","NotificationManager", 'logs/log_v6.4.txt')
    search_generic(".java","sendBroadcast", 'logs/log_v6.4.txt')
    search_generic(".java","sendOrderedBroadcast", 'logs/log_v6.4.txt')
    search_generic(".java","sendStickyBroadcast", 'logs/log_v6.4.txt')
    search_generic(".java","sendStickyOrderedBroadcast", 'logs/log_v6.4.txt')
    globals.write_to_file("\nEND OF: Execution log for V6.4\n", "logs/log_v6.4.txt")
    print("Completed V6.4 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.5
#Cheat Sheet:
#Search for 'setJavaScriptEnabled'. The default is false.
#Details:
#Verify that JavaScript is disabled in WebViews unless explicitly required.
#**************************************************************************
def search_setJavaScriptEnabled():
    globals.write_to_file("START OF: Execution log for V6.5\n", "logs/log_v6.5.txt")
    search_generic(".java","WebView", 'logs/log_v6.5.txt')
    search_generic(".java","setJavaScriptEnabled", 'logs/log_v6.5.txt')
    globals.write_to_file("\nEND OF: Execution log for V6.5\n", "logs/log_v6.5.txt")
    print("Completed V6.5 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.6
#Cheat Sheet:
#Search for "setAllowContentAccess", "setAllowFileAccess",
#"setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs"
#Details:
#Verify that WebViews are configured to allow only the minimum set of protocol
#  handlers required (ideally, only https). Potentially dangerous handlers,
#  such as file, tel and app-id, are disabled.
#**************************************************************************
def search_webview_config():
    globals.write_to_file("START OF: Execution log for V6.6\n", "logs/log_v6.6.txt")
    search_generic(".java","setAllowContentAccess", 'logs/log_v6.6.txt')
    search_generic(".java","setAllowFileAccess", 'logs/log_v6.6.txt')
    search_generic(".java","setAllowFileAccessFromFileURLs", 'logs/log_v6.6.txt')
    search_generic(".java","setAllowUniversalAccessFromFileURLs", 'logs/log_v6.6.txt')
    globals.write_to_file("\nEND OF: Execution log for V6.6\n", "logs/log_v6.6.txt")
    print("Completed V6.6 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.7
#Cheat Sheet:
#Search for 'addjavascriptinterface('
#Details:
#If native methods of the app are exposed to a WebView, verify that the
# WebView only renders JavaScript contained within the app package.
#**************************************************************************
def search_addjavascriptinterface():
    globals.write_to_file("START OF: Execution log for V6.7\n", "logs/log_v6.7.txt")
    search_generic(".java","addjavascriptinterface", 'logs/log_v6.7.txt')
    globals.write_to_file("\nEND OF: Execution log for V6.7\n", "logs/log_v6.7.txt")
    print("Completed V6.7 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.8
#Cheat Sheet:
#Search for 'implements Serializable', 'implements Parcelable'
#Details:
#Verify that object serialization, if any, is implemented using safe
# serialization APIs.
#**************************************************************************
def search_serialization():
    globals.write_to_file("START OF: Execution log for V6.8\n", "logs/log_v6.8.txt")
    search_generic(".java","implements Serializable", 'logs/log_v6.8.txt')
    search_generic(".java","implements Parcelable", 'logs/log_v6.8.txt')
    globals.write_to_file("\nEND OF: Execution log for V6.8\n", "logs/log_v6.8.txt")
    print("Completed V6.8 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 7.4
#Cheat Sheet:
#Search for 'debug', 'proxy'
#Details:
#Verify that debugging code has been removed, and the app does not log
# verbose errors or debugging messages.
#**************************************************************************
def search_debugging_code():
    globals.write_to_file("START OF: Execution log for V7.4\n", "logs/log_v7.4.txt")
    search_generic(".java","debug", 'logs/log_v7.4.txt')
    search_generic(".java","proxy", 'logs/log_v7.4.txt')
    search_generic(".java","test", 'logs/log_v7.4.txt')
    search_generic(".java","uat", 'logs/log_v7.4.txt')
    search_generic(".java","demo", 'logs/log_v7.4.txt')
    globals.write_to_file("\nEND OF: Execution log for V7.4\n", "logs/log_v7.4.txt")
    print("Completed V7.4 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 7.9
#Cheat Sheet:
#Search for "minifyEnabled", "shrinkResources",
#Details:
#Free security features offered by the toolchain, such as byte-code
# minification, stack protection, PIE support and automatic reference counting,
# are activated.
#**************************************************************************
def search_gradle():
    globals.write_to_file("START OF: Execution log for V7.9\n", "logs/log_v7.9.txt")
    search_generic(".gradle","minifyEnabled", 'logs/log_v7.9.txt')
    search_generic(".gradle","shrinkResources", 'logs/log_v7.9.txt')
    globals.write_to_file("\nEND OF: Execution log for V7.9\n", "logs/log_v7.9.txt")
    print("Completed V7.9 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


#**************************************************************************
#OWASP MASVS v1.0 point 8.1
#Cheat Sheet:
#Search for "RootBeer", "SafetyNet",
#Details:
#we define "root detection" a bit more broadly, including custom ROMs 
#detection, i.e., determining whether the device is a stock Android build or 
#a custom build.
#**************************************************************************
def search_root_detect():
    globals.write_to_file("START OF: Execution log for V8.1\n", "logs/log_v8.1.txt")
    search_generic(".java","RootBeer", 'logs/log_v8.1.txt')
    search_generic(".java","SafetyNet", 'logs/log_v8.1.txt')
    search_generic(".java","ctsProfileMatch", 'logs/log_v8.1.txt')
    search_generic(".java","basicIntegrity", 'logs/log_v8.1.txt')
    search_generic(".java","nonces", 'logs/log_v8.1.txt')
    search_generic(".java","timestampMs", 'logs/log_v8.1.txt')
    search_generic(".java","apkPackageName", 'logs/log_v8.1.txt')
    search_generic(".java","apkCertificateDigestSha256", 'logs/log_v8.1.txt')
    search_generic(".java","apkDigestSha256", 'logs/log_v8.1.txt')
    search_generic(".java","Superuser", 'logs/log_v8.1.txt')
    search_generic(".java","/sbin/su", 'logs/log_v8.1.txt')
    search_generic(".java","/system/bin/su", 'logs/log_v8.1.txt')
    search_generic(".java","/system/bin/failsafe/su", 'logs/log_v8.1.txt')
    search_generic(".java","/system/xbin/su", 'logs/log_v8.1.txt')
    search_generic(".java","/system/xbin/busybox", 'logs/log_v8.1.txt')
    search_generic(".java","/system/sd/xbin/su", 'logs/log_v8.1.txt')
    search_generic(".java","/data/local/su", 'logs/log_v8.1.txt')
    search_generic(".java","/data/local/xbin/su", 'logs/log_v8.1.txt')
    search_generic(".java","/data/local/bin/su", 'logs/log_v8.1.txt')
    
    search_generic(".java","getenv", 'logs/log_v8.1.txt')
    search_generic(".java","JNIEnv", 'logs/log_v8.1.txt')
    search_generic(".java","jobject", 'logs/log_v8.1.txt')
    search_generic(".java","jstring", 'logs/log_v8.1.txt')
    search_generic(".java","struct stat", 'logs/log_v8.1.txt')
    search_generic(".c","getenv", 'logs/log_v8.1.txt')
    search_generic(".c","JNIEnv", 'logs/log_v8.1.txt')
    search_generic(".c","jobject", 'logs/log_v8.1.txt')
    search_generic(".c","jstring", 'logs/log_v8.1.txt')
    search_generic(".c","struct stat", 'logs/log_v8.1.txt')
    
    search_generic(".java","getRuntime", 'logs/log_v8.1.txt')
    search_generic(".java","getRunningAppProcesses", 'logs/log_v8.1.txt')
    search_generic(".java","getRunningServices", 'logs/log_v8.1.txt')
    search_generic(".java","RunningServiceInfo", 'logs/log_v8.1.txt')
    search_generic(".java","com.thirdparty.superuser", 'logs/log_v8.1.txt')
    search_generic(".java","eu.chainfire.supersu", 'logs/log_v8.1.txt')
    search_generic(".java","com.noshufou.android.su", 'logs/log_v8.1.txt')
    search_generic(".java","com.koushikdutta.superuser", 'logs/log_v8.1.txt')
    search_generic(".java","com.zachspong.temprootremovejb", 'logs/log_v8.1.txt')
    search_generic(".java","com.ramdroid.appquarantine", 'logs/log_v8.1.txt')
    search_generic(".java","com.topjohnwu.magisk", 'logs/log_v8.1.txt')
    search_generic(".java","Build.TAGS", 'logs/log_v8.1.txt')
    search_generic(".java","test-keys", 'logs/log_v8.1.txt')
    search_generic(".java","jdb", 'logs/log_v8.1.txt')
    search_generic(".java","strace", 'logs/log_v8.1.txt')
    search_generic(".java","/proc", 'logs/log_v8.1.txt')
    
    search_hardcode("DDMS", 'logs/log_v8.1.txt')
    search_hardcode("Frida", 'logs/log_v8.1.txt')
    search_hardcode("Xposed", 'logs/log_v8.1.txt')
    search_hardcode("RootCloak", 'logs/log_v8.1.txt')

    globals.write_to_file("\nEND OF: Execution log for V8.1\n", "logs/log_v8.1.txt")
    print("Completed V8.1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 8.2
#Cheat Sheet:
#Search for "jdwp"
#Details:
#Debugging is a highly effective way to analyze runtime app behavior. It 
#allows the reverse engineer to step through the code, stop app execution 
#at arbitrary points, inspect the state of variables, read and modify 
#memory, and a lot more.
#**************************************************************************
def search_anti_debug():
    globals.write_to_file("START OF: Execution log for V8.2\n", "logs/log_v8.2.txt")
    search_generic(".java","jdwp", 'logs/log_v8.2.txt')
    search_generic(".java","ro.debuggable", 'logs/log_v8.2.txt')
    search_generic(".java","FLAG_DEBUGGABLE", 'logs/log_v8.2.txt')
    search_generic(".java","isDebuggerConnected ", 'logs/log_v8.2.txt')
    search_generic(".java","JNIEXPORT", 'logs/log_v8.2.txt')
    search_generic(".java","JNICALL", 'logs/log_v8.2.txt')
    search_generic(".java","gDvm", 'logs/log_v8.2.txt')
    search_generic(".java","debuggerConnected", 'logs/log_v8.2.txt')
    search_generic(".java","debuggerActive", 'logs/log_v8.2.txt')
    search_generic(".java","JNI_TRUE", 'logs/log_v8.2.txt')
    search_generic(".java","JNI_FALSE", 'logs/log_v8.2.txt')
    search_generic(".java","threadCpuTimeNanos", 'logs/log_v8.2.txt')
    search_generic(".java","DvmGlobals", 'logs/log_v8.2.txt')
    search_generic(".java","jdwpAllowed", 'logs/log_v8.2.txt')
    search_generic(".java","jdwpConfigured", 'logs/log_v8.2.txt')
    search_generic(".java","JdwpTransportType", 'logs/log_v8.2.txt')
    search_generic(".java","JdwpState", 'logs/log_v8.2.txt')
    search_generic(".java","methDalvikDdmcServer_dispatch", 'logs/log_v8.2.txt')
    search_generic(".java","JdwpSocketState", 'logs/log_v8.2.txt')
    search_generic(".java","JdwpAdbState", 'logs/log_v8.2.txt')
    search_generic(".java","ProcessIncoming", 'logs/log_v8.2.txt')
    search_generic(".java","Shutdown", 'logs/log_v8.2.txt')
    search_generic(".java","JDWPFun", 'logs/log_v8.2.txt')
    search_generic(".java","mman.h", 'logs/log_v8.2.txt')
    search_generic(".java","jdwp.h", 'logs/log_v8.2.txt')
    search_generic(".java","##__VA_ARGS__", 'logs/log_v8.2.txt')
    search_generic(".java","libart.so", 'logs/log_v8.2.txt')
    search_generic(".java","RTLD_NOW", 'logs/log_v8.2.txt')
    search_generic(".java","libart.so", 'logs/log_v8.2.txt')
    search_generic(".java","mprotect", 'logs/log_v8.2.txt')
    search_generic(".java","ptrace", 'logs/log_v8.2.txt')
    search_generic(".java","/status", 'logs/log_v8.2.txt')
    search_generic(".java","TracerPid", 'logs/log_v8.2.txt')
    search_generic(".java","hasTracerPid", 'logs/log_v8.2.txt')
    search_generic(".java","IsDebuggerAttached", 'logs/log_v8.2.txt')
    search_generic(".java","PTRACE_ATTACH", 'logs/log_v8.2.txt')
    search_generic(".java","PTRACE_CONT", 'logs/log_v8.2.txt')
    search_generic(".java","getppid", 'logs/log_v8.2.txt')
    search_generic(".java","fork", 'logs/log_v8.2.txt')
    search_generic(".java","waitpid", 'logs/log_v8.2.txt')
    search_generic(".java","pthread", 'logs/log_v8.2.txt')
    search_generic(".java","WIFSTOPPED", 'logs/log_v8.2.txt')
    search_generic(".java","pthread", 'logs/log_v8.2.txt')
    search_generic(".java","libc.so", 'logs/log_v8.2.txt')
    search_generic(".java","_exit", 'logs/log_v8.2.txt')

    search_generic(".c","JNIEXPORT", 'logs/log_v8.2.txt')
    search_generic(".c","JNICALL", 'logs/log_v8.2.txt')
    search_generic(".c","gDvm", 'logs/log_v8.2.txt')
    search_generic(".c","debuggerConnected", 'logs/log_v8.2.txt')
    search_generic(".c","debuggerActive", 'logs/log_v8.2.txt')
    search_generic(".c","JNI_TRUE", 'logs/log_v8.2.txt')
    search_generic(".c","JNI_FALSE", 'logs/log_v8.2.txt')
    search_generic(".c","threadCpuTimeNanos", 'logs/log_v8.2.txt')
    search_generic(".c","DvmGlobals", 'logs/log_v8.2.txt')
    search_generic(".c","jdwpAllowed", 'logs/log_v8.2.txt')
    search_generic(".c","jdwpConfigured", 'logs/log_v8.2.txt')
    search_generic(".c","JdwpTransportType", 'logs/log_v8.2.txt')
    search_generic(".c","JdwpState", 'logs/log_v8.2.txt')
    search_generic(".c","methDalvikDdmcServer_dispatch", 'logs/log_v8.2.txt')
    search_generic(".c","JdwpSocketState", 'logs/log_v8.2.txt')
    search_generic(".c","JdwpAdbState", 'logs/log_v8.2.txt')
    search_generic(".c","ProcessIncoming", 'logs/log_v8.2.txt')
    search_generic(".c","Shutdown", 'logs/log_v8.2.txt')
    search_generic(".c","JDWPFun", 'logs/log_v8.2.txt')
    search_generic(".c","mman.h", 'logs/log_v8.2.txt')
    search_generic(".c","jdwp.h", 'logs/log_v8.2.txt')
    search_generic(".c","##__VA_ARGS__", 'logs/log_v8.2.txt')
    search_generic(".c","libart.so", 'logs/log_v8.2.txt')
    search_generic(".c","RTLD_NOW", 'logs/log_v8.2.txt')
    search_generic(".c","libart.so", 'logs/log_v8.2.txt')
    search_generic(".c","mprotect", 'logs/log_v8.2.txt')
    search_generic(".c","ptrace", 'logs/log_v8.2.txt')
    search_generic(".c","/status", 'logs/log_v8.2.txt')
    search_generic(".c","TracerPid", 'logs/log_v8.2.txt')
    search_generic(".c","hasTracerPid", 'logs/log_v8.2.txt')
    search_generic(".c","IsDebuggerAttached", 'logs/log_v8.2.txt')
    search_generic(".c","PTRACE_ATTACH", 'logs/log_v8.2.txt')
    search_generic(".c","PTRACE_CONT", 'logs/log_v8.2.txt')
    search_generic(".c","getppid", 'logs/log_v8.2.txt')
    search_generic(".c","fork", 'logs/log_v8.2.txt')
    search_generic(".c","waitpid", 'logs/log_v8.2.txt')
    search_generic(".c","pthread", 'logs/log_v8.2.txt')
    search_generic(".c","WIFSTOPPED", 'logs/log_v8.2.txt')
    search_generic(".c","pthread", 'logs/log_v8.2.txt')
    search_generic(".c","libc.so", 'logs/log_v8.2.txt')
    search_generic(".c","_exit", 'logs/log_v8.2.txt')

    globals.write_to_file("\nEND OF: Execution log for V8.2\n", "logs/log_v8.2.txt")
    print("Completed V8.2 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


#**************************************************************************
#OWASP MASVS v1.0 point 8.3
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Code integrity checks and The file storage integrity checks
#**************************************************************************
def search_integrity_check():
    globals.write_to_file("START OF: Execution log for V8.3\n", "logs/log_v8.3.txt")
    search_generic(".java","getPackageCodePath", 'logs/log_v8.3.txt')
    search_generic(".java","dex_crc", 'logs/log_v8.3.txt')
    search_generic(".java","ZipFile", 'logs/log_v8.3.txt')
    search_generic(".java","ZipEntry", 'logs/log_v8.3.txt')
    search_generic(".java","getCrc", 'logs/log_v8.3.txt')
    search_generic(".java","hmac", 'logs/log_v8.3.txt')
    search_generic(".java","BouncyCastle", 'logs/log_v8.3.txt')
    search_generic(".java","SpongyCastle", 'logs/log_v8.3.txt')
    search_generic(".java","getMacLength", 'logs/log_v8.3.txt')
    search_generic(".java","classes.dex", 'logs/log_v8.3.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V8.3\n", "logs/log_v8.3.txt")
    print("Completed V8.3 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 8.4
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Reverse Engineering Tools
#**************************************************************************
def search_reverse_tools():
    globals.write_to_file("START OF: Execution log for V8.4\n", "logs/log_v8.4.txt")
    search_hardcode("Substrate", 'logs/log_v8.4.txt')
    search_hardcode("Xposed", 'logs/log_v8.4.txt')
    search_hardcode("Frida", 'logs/log_v8.4.txt')
    
    search_generic(".java","frida-trace", 'logs/log_v8.4.txt')
    search_generic(".java","LD_PRELOAD", 'logs/log_v8.4.txt')
    search_generic(".java","DYLD_INSERT_LIBRARIES", 'logs/log_v8.4.txt')
    search_generic(".java","libgadget", 'logs/log_v8.4.txt')
    search_generic(".java","gdbserver", 'logs/log_v8.4.txt')
    search_generic(".java","LD_PRELOAD", 'logs/log_v8.4.txt')
    search_generic(".java","FridaGadget", 'logs/log_v8.4.txt')
    search_generic(".java","GET_SIGNING_CERTIFICATES", 'logs/log_v8.4.txt')
    search_generic(".java","frida-server", 'logs/log_v8.4.txt')
    search_generic(".java","frida-gadget", 'logs/log_v8.4.txt')
    search_generic(".java","frida-agent", 'logs/log_v8.4.txt')
    search_generic(".java","27042", 'logs/log_v8.4.txt')
    search_generic(".java","LIBFRIDA", 'logs/log_v8.4.txt')
    search_generic(".java","Runtime.getRuntime().exec", 'logs/log_v8.4.txt')
    search_generic(".java","/proc/self/maps", 'logs/log_v8.4.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V8.4\n", "logs/log_v8.4.txt")
    print("Completed V8.4 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


#**************************************************************************
#OWASP MASVS v1.0 point 8.5
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Emulator Detection
#**************************************************************************
def search_emulator_detect():
    globals.write_to_file("START OF: Execution log for V8.5\n", "logs/log_v8.5.txt")
    search_generic(".java","build.prop", 'logs/log_v8.5.txt')
    search_generic(".java","Build.ABI", 'logs/log_v8.5.txt')
    search_generic(".java","BUILD.ABI2", 'logs/log_v8.5.txt')
    search_generic(".java","Build.BOARD", 'logs/log_v8.5.txt')
    search_generic(".java","Build.Brand", 'logs/log_v8.5.txt')
    search_generic(".java","Build.DEVICE", 'logs/log_v8.5.txt')
    search_generic(".java","Build.FINGERPRINT", 'logs/log_v8.5.txt')
    search_generic(".java","Build.Hardware", 'logs/log_v8.5.txt')
    search_generic(".java","Build.Host", 'logs/log_v8.5.txt')
    search_generic(".java","Build.ID", 'logs/log_v8.5.txt')
    search_generic(".java","Build.MANUFACTURER", 'logs/log_v8.5.txt')
    search_generic(".java","Build.MODEL", 'logs/log_v8.5.txt')
    search_generic(".java","Build.PRODUCT", 'logs/log_v8.5.txt')
    search_generic(".java","Build.RADIO", 'logs/log_v8.5.txt')
    search_generic(".java","Build.SERIAL", 'logs/log_v8.5.txt')
    search_generic(".java","Build.USER", 'logs/log_v8.5.txt')
    search_generic(".java","armeabi", 'logs/log_v8.5.txt')
    search_generic(".java","generic", 'logs/log_v8.5.txt')
    search_generic(".java","goldfish", 'logs/log_v8.5.txt')
    search_generic(".java","goldfish", 'logs/log_v8.5.txt')
    search_generic(".java","FRF91", 'logs/log_v8.5.txt')
    search_generic(".java","android-build", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getDeviceId", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getLine1", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getNetworkCountryIso", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getNetworkType", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getNetworkOperator", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getPhoneType", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getSimCountryIso", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getSimSerial", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getSubscriberId", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getVoiceMailNumber", 'logs/log_v8.5.txt')
    search_generic(".java","155552155", 'logs/log_v8.5.txt')
    search_generic(".java","89014103211118510720", 'logs/log_v8.5.txt')
    search_generic(".java","310260000000000", 'logs/log_v8.5.txt')
    search_generic(".java","15552175049", 'logs/log_v8.5.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V8.5\n", "logs/log_v8.5.txt")
    print("Completed V8.5 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


#**************************************************************************
#OWASP MASVS v1.0 point 8.6
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Runtime Integrity Checks
#**************************************************************************
def search_runtime_integrity():
    globals.write_to_file("START OF: Execution log for V8.6\n", "logs/log_v8.6.txt")
    search_generic(".java","zygoteInitCallCount", 'logs/log_v8.6.txt')
    search_generic(".java","StackTraceElement", 'logs/log_v8.6.txt')
    search_generic(".java","stackTraceElement.getMethodName", 'logs/log_v8.6.txt')
    search_generic(".java","com.android.internal.os.ZygoteInit", 'logs/log_v8.6.txt')
    search_generic(".java","com.saurik.substrate.MS$2", 'logs/log_v8.6.txt')
    search_generic(".java","de.robv.android.xposed.XposedBridge", 'logs/log_v8.6.txt')
    search_generic(".java","stackTraceElement.getClassName", 'logs/log_v8.6.txt')
    search_generic(".java","handleHookedMethod", 'logs/log_v8.6.txt')
    search_generic(".java","trampoline", 'logs/log_v8.6.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V8.6\n", "logs/log_v8.6.txt")
    print("Completed V8.6 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 8.9
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Obfuscation
#**************************************************************************
def search_obfuscation():
    globals.write_to_file("START OF: Execution log for V8.9\n", "logs/log_v8.9.txt")
    search_hardcode("proguard", 'logs/log_v8.9.txt')
    search_hardcode("R8", 'logs/log_v8.9.txt')
    search_hardcode("obfuscat", 'logs/log_v8.9.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V8.9\n", "logs/log_v8.9.txt")
    print("Completed V8.9 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 8.10
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Device Binding
#**************************************************************************
def search_device_bind():
    globals.write_to_file("START OF: Execution log for V8.10\n", "logs/log_v8.10.txt")
    search_generic(".java","KeyGenParameterSpec", 'logs/log_v8.10.txt')
    search_generic(".java","KEY_ALGORITHM_RSA", 'logs/log_v8.10.txt')
    search_generic(".java","PURPOSE_DECRYPT", 'logs/log_v8.10.txt')
    search_generic(".java","DIGEST_SHA256", 'logs/log_v8.10.txt')
    search_generic(".java","DIGEST_SHA512", 'logs/log_v8.10.txt')
    search_generic(".java","ENCRYPTION_PADDING_RSA_OAEP", 'logs/log_v8.10.txt')
    search_generic(".java","PURPOSE_ENCRYPT", 'logs/log_v8.10.txt')
    search_generic(".java","OAEPWithSHA", 'logs/log_v8.10.txt')
    search_generic(".java","BLOCK_MODE_GCM", 'logs/log_v8.10.txt')
    search_generic(".java","ENCRYPTION_PADDING_NONE", 'logs/log_v8.10.txt')
    search_generic(".java","NoPadding", 'logs/log_v8.10.txt')
    search_generic(".java","GCM_NONCE_LENGTH", 'logs/log_v8.10.txt')
    search_generic(".java","GCM_TAG_LENGTH", 'logs/log_v8.10.txt')
    search_generic(".java","GCMParameterSpec", 'logs/log_v8.10.txt')
    search_generic(".java","updateAAD", 'logs/log_v8.10.txt')
    search_generic(".java","ENCRYPT_MODE", 'logs/log_v8.10.txt')
    search_generic(".java","DECRYPT_MODE", 'logs/log_v8.10.txt')
    search_generic(".java","Cipher.getInstance", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.ANDROID_ID", 'logs/log_v8.10.txt')
    search_generic(".java","AdvertisingIdClient", 'logs/log_v8.10.txt')
    search_generic(".java","AdvertisingIdClient", 'logs/log_v8.10.txt')
    search_generic(".java","FirebaseInstanceId", 'logs/log_v8.10.txt')
    search_generic(".java","SSAID", 'logs/log_v8.10.txt')
    search_generic(".java","Build.getSerial", 'logs/log_v8.10.txt')
    search_generic(".java","Build.SERIAL", 'logs/log_v8.10.txt')
    search_generic(".java","htc.camera.sensor.front_SN", 'logs/log_v8.10.txt')
    search_generic(".java","persist.service.bdroid.bdadd", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.bluetooth_address", 'logs/log_v8.10.txt')
    search_generic(".java","WifiInfo.getMacAddress", 'logs/log_v8.10.txt')
    search_generic(".java","LOCAL_MAC_ADDRESS", 'logs/log_v8.10.txt')
    search_generic(".java","TELEPHONY_SERVICE", 'logs/log_v8.10.txt')
    search_generic(".java","getInstance", 'logs/log_v8.10.txt')
    search_generic(".java","Instance", 'logs/log_v8.10.txt')
    search_generic(".java","getId", 'logs/log_v8.10.txt')
    search_generic(".java","getToken", 'logs/log_v8.10.txt')
    search_generic(".java","getDeviceId", 'logs/log_v8.10.txt')
    search_generic(".java","IDListenerService", 'logs/log_v8.10.txt')
    search_generic(".java","FirebaseInstanceId", 'logs/log_v8.10.txt')
    search_generic(".java","android.os.Build.SERIAL", 'logs/log_v8.10.txt')
    search_generic(".java","android.os.Build.getSerial", 'logs/log_v8.10.txt')
    search_generic(".java","TELEPHONY_SERVICE", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.ANDROID_ID", 'logs/log_v8.10.txt')
    search_generic(".java","persist.service.bdroid.bdadd", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.bluetooth_address", 'logs/log_v8.10.txt')
    search_generic(".java","WifiInfo.getMacAddress", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.ANDROID_ID", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.ANDROID_ID", 'logs/log_v8.10.txt')
        

    search_generic(".xml","READ_PHONE_STATE", 'logs/log_v8.10.txt')
    search_generic(".xml","LOCAL_MAC_ADDRESS", 'logs/log_v8.10.txt')

    globals.write_to_file("\nEND OF: Execution log for V8.10\n", "logs/log_v8.10.txt")
    print("Completed V8.10 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")














    
