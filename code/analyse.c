#include "main.h"
extern static char buffer[PATH_MAX];

/*enum permission {SEND_SMS = 1, RECEIVE_SMS, RECEIVE_SMS, CALL_PHONE, READ_CALL_LOG, WRITE_CALL_LOG, RECORD_AUDIO, CAMERA,
READ CONTACTS, WRITE_CONTACTS, ACCESS_FINE_LOCATION, INTERNET, SYSTEM_ALERT_WINDOW, INSTALL_PACKAGES,
READ_EXTERNAL_STORAGE};*/
int main(void)
{
    while(!buffer)
    {   
        system("grep -E 'permissions' AndroidManifest.xml > test.txt" );
    }
    
}