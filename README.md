# win-work-logger
Reads unlock/lock events of windows and calculates active time from the events.
Perhaps windows already support this feature out of box - but this was more fun.

## To enable unlock/lock events in windows:
1. Open Local Group Policy Editor
2. Click on "Logon/Logoff" under 
Computer Configuration>Windows Settings>Security Settings>Advanced Audit Policy Configuration>System Audit Policies - Local Group Policy Object>Logon/Logoff
3. Configure subcategory "Audit Other Logon/Logoff Events" to be Success and Failure

## Dependencies:
* Tested on python3.11 only
* pywin32
* pyuac