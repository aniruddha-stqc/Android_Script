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


