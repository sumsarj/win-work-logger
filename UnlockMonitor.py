import win32evtlog
import winerror
import time
import re
import sys
import getopt
from pyuac import main_requires_admin



debugLogging=False
def printDebug(*args):
    
    '''

    Print only if debug logs (verbose) is enabled

    '''
    if debugLogging == True:
        print("DGB: ",*args)

def date2sec(evt_date, format = "%m/%d/%Y %H:%M:%S"):

    '''

    Coverts dates with specified 
    format to seconds since epoch.
    Supported formats:
    "%m/%d/%Y %H:%M:%S",
    "%y-%m-%d %H:%M:%S"

    '''
    date=""
    the_time=""
    yr=0
    mon=0
    day=0
    hr=0
    min=0
    sec=0
    #could probably generalize this instead of is elif etc..
    if format == "%m/%d/%Y %H:%M:%S":
        regexp=re.compile('(.*)\\s(.*)') #store result in site

        reg_result=regexp.search(evt_date)

        if(reg_result is None):
            assert(False)

        date=reg_result.group(1)

        the_time=reg_result.group(2)
        (mon,day,yr)=map(lambda x: int(x),date.split('/'))

        (hr,min,sec)=map(lambda x: int(x),the_time.split(':'))
    elif format == "%y-%m-%d %H:%M:%S":
        regexp=re.compile('(.*)\\s(.*)') #store result in site

        reg_result=regexp.search(evt_date)
        if(reg_result is None):
            assert(False)
        date=reg_result.group(1)

        the_time=reg_result.group(2)
        (yr,mon,day)=map(lambda x: int(x),date.split('-'))
        yr = 2000+yr

        (hr,min,sec)=map(lambda x: int(x),the_time.split(':'))
    else:
        assert(False)

    tup=(yr,mon,day,hr,min,sec,0,1,-1)


    sec=time.mktime(tup)



    return sec

@main_requires_admin
def main():
    global debugLogging
    current_sec=time.time()

    current_time=time.strftime('%H:%M:%S  ',time.localtime(current_sec))
    current_date_messed_up=time.strftime('%m/%d/%Y ',time.localtime(current_sec))
    current_date=time.strftime('%y-%m-%d ',time.localtime(current_sec))
    printDebug(current_time)
    start_sec=0
    end_sec=0
    start_time=""
    end_time=""
    printDebug(str(sys.argv))

    opts, args = getopt.getopt(sys.argv[1:],"hvs:e:d:",["start-time=","end-time=","date=","--verbose"])
    printDebug(args)
    #print(opts)
    printDebug(opts)
    #print(str(debugLogging))
    for opt, arg in opts:
        if opt in ("-d", "--date"):
            current_date=arg+" "
            bla=date2sec(current_date+" 10:00:00","%y-%m-%d %H:%M:%S")
            current_date_messed_up=time.strftime('%m/%d/%Y ',time.localtime(bla))
            printDebug("#"+current_date_messed_up+current_time[0:-2]+"#")
            current_sec=date2sec(current_date_messed_up+current_time[0:-2])
            printDebug(current_time)
        elif opt in ("-v", "--verbose"):
            debugLogging=True


    for opt, arg in opts:
        if opt == '-h':
            print ('test.py -s HH:MM -e HH:MM')
            sys.exit()
        elif opt in ("-s", "--start-time"):
            printDebug(arg)
            arg+=":00"
            bla=current_date_messed_up+arg
            start_time=current_date+arg
            start_sec=date2sec(bla)
            printDebug(start_sec)

        elif opt in ("-e", "--end-time"):
            printDebug(arg)
            arg+=":00"
            bla=current_date_messed_up+arg
            end_time=current_date+arg
            end_sec=date2sec(bla)
            printDebug(end_sec)

            
    if end_sec == 0:
        end_sec=current_sec
        end_time=time.strftime('%y-%m-%d %H:%M:%S',time.localtime(current_sec))
    if start_sec == 0:
        start_sec=end_sec-float(12*60*60)
        start_time=time.strftime('%y-%m-%d %H:%M:%S',time.localtime(start_sec))

    #open event log
    print("Start-time: "+start_time)
    print("End-time: "+end_time)

    #We want to read backwards, meaning that we read most recent events first.
    #This is to avoid reading through very old events before we reach the new juicy ones
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|\
        win32evtlog.EVENTLOG_SEQUENTIAL_READ

    logtype='Security' #This is where the unlock/lock events are logged.
    hand=win32evtlog.OpenEventLog(None,logtype)

    printDebug (logtype,' events found in the last 8 hours since:',start_time)



    #try:
    printDebug(start_sec)
    printDebug(end_sec)
    events=1
    eventList=[]
    seconds=0.0
    while events:

        events=win32evtlog.ReadEventLog(hand,flags,0)
        for ev_obj in events:
            #check if the event is recent enough

            #only want data from last 8hrs
            evt_id=str(winerror.HRESULT_CODE(ev_obj.EventID))

            the_time=ev_obj.TimeGenerated.Format("%m/%d/%Y %H:%M:%S")

            seconds=date2sec(the_time)
            #4800 is Locked, 4801 is unlocked. we are not interested in other events
            if not (evt_id == "4800" or evt_id == "4801"):
                continue

            if (seconds < start_sec): break #we are now processing too old events
            if (seconds > end_sec): continue #the events are still newer than we are interested in



            #data is recent enough, so print it out

            #computer=str(ev_obj.ComputerName)

            #cat=str(ev_obj.EventCategory)

            #src=str(ev_obj.SourceName)

            #record=str(ev_obj.RecordNumber)

            evt_id=str(winerror.HRESULT_CODE(ev_obj.EventID))
            ev="UNLOCKED"
            if (evt_id == "4800"):
                ev="LOCKED"

            #evt_type=str(evt_dict[ev_obj.EventType])

            #msg = str(win32evtlogutil.SafeFormatMessage(ev_obj, logtype))
            #printDebug(":".join((the_time,computer,src,cat,record,evt_id,evt_type,msg[0:27])))
            printDebug(". ".join((the_time,ev)))
            eventList.append((evt_id,seconds))

        if (seconds < start_sec): 
            printDebug(str(seconds))
            break #get out of while loop as well

    win32evtlog.CloseEventLog(hand)
    if len(eventList) == 0:
        print("No events logged.")
        sys.exit(0)
    totalTimeUnlocked=0
    totalTimeLocked=0
    lastUnlockedTime=0
    lastLockedTime=0
    checkinTime=0
    eventList.reverse()
    printDebug(len(eventList))
    if eventList[-1][0] == "4801":
        eventList.append(("4800",end_sec))

    printDebug(len(eventList))
    for (evt_id,seconds) in eventList:
        printDebug(evt_id)
        printDebug(seconds)
        log_id=""
        timeInPrevState=0
        if evt_id == "4800": #locked
            log_id="LOCKED"
            if lastUnlockedTime == 0:
                continue
            activeTime=seconds-lastUnlockedTime
            timeInPrevState=round(activeTime/60,2)
            totalTimeUnlocked += activeTime
            lastLockedTime = seconds
        elif evt_id == "4801": #unlocked
            log_id="UNLOCKED"
            if lastLockedTime == 0:
                lastLockedTime = seconds
                checkinTime = seconds
            inactiveTime=seconds-lastLockedTime
            timeInPrevState=round(inactiveTime/60,2)
            totalTimeLocked += inactiveTime
            lastUnlockedTime = seconds
        else:
            print("SATAN")
            log_id="UNKNOWN"
        timeStr=time.strftime('%H:%M:%S',time.localtime(seconds))
        if timeInPrevState > 0.0:
            print("     for: "+str(timeInPrevState))
        print(timeStr+": "+log_id)
        
    print("Check-in time: "+time.strftime('%H:%M:%S  ',time.localtime(checkinTime)))
    print("Time away from PC: "+str(round(totalTimeLocked/60,2))+"m")
    print("Time at PC: "+str(round(totalTimeUnlocked/60,2))+" ("+str(round(totalTimeUnlocked/60/60,2))+"h)")
    print("Total time in office: "+str(round((totalTimeLocked+totalTimeUnlocked)/60/60,2))+"h")
    #except:

    #    print(traceback.print_exc(sys.exc_info()))

if __name__ == "__main__":
    main()
