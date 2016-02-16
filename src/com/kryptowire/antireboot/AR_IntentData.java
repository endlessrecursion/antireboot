package com.kryptowire.antireboot;

public class AR_IntentData {

	/* This class is a container class that contains various
	 * data about an intent that was sniffed from the log.
	 */	
	
	// the PID of the process that wrote to the log
    int logAuthorPid;
    
    // the PID of the process that sent the intent
    int sourcePid;
    
    // the UID of the process that sent the intent
    int uid;
    
    // the log tag from the log entry
    String logtag;
    
    // the action, if present, of the intent
    String action;
    
    // the package name that is the destination of the intent
    String packageName;
    
    // the flags of the intent
    int flags;
    
    // the component that will be started by the intent
    String component;
    
    public AR_IntentData(int logAuthorPid, int sourcePid, int uid, String activity, String action, String packageName, int flags, String component) {
      this.logAuthorPid = logAuthorPid;
      this.sourcePid = sourcePid;
      this.uid = uid;
      this.logtag = activity;
      this.action = action;
      this.packageName = packageName;
      this.flags = flags;
      this.component = component;
    }

    @Override
    public String toString() {
      return "IntentData [logAuthorPid=" + logAuthorPid + ", sourcePid=" + sourcePid + ", uid=" + uid + ", logtag=" + logtag + ", action=" + action
          + ", package=" + packageName + ", flags=" + flags + ", component=" + component + "]";
    }
    
}
