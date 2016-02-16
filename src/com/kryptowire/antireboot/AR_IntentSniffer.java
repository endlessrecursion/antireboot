package com.kryptowire.antireboot;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import android.util.Log;

public class AR_IntentSniffer {

	/* The AR_IntentSniffer class will examine the Android log and pass
	 * back an AR_IntentData object when an intent launch is encountered
	 * in the Android log. This class uses regex to search the log entries.
	 * The intentRegex is set up for AOSP log entries for intents. If the
	 * device does not match this regex then an exception for the device
	 * can be entered in the static block by using the build fingerprint
	 * of the device. This is only necessary if the intentRegex does not
	 * match the launching of intents as they appear in the Android log.
	 * 
	 */
	
	// the log tag	
	private final static String TAG = AR_IntentSniffer.class.getName();

	// if true, debug statements will be sent to the log
	private final static boolean DEBUG = AR_Constants.DEBUG;

	// the regex used to find and process log messages corresponding
	// to the launching of an intent. this regex is general in that
	// it works on Android 4.4.2 and 6.0.1
	//private static String intentRegex = "^\\w\\(\\s*(\\d+)\\) START \\w+ \\{(.*)\\} from pid (\\d+) .* \\(([\\w\\.]+)\\)$";
	private static String intentRegex = "^\\w\\(\\s*(\\d+)\\) START \\w+ \\{(.*)\\} from ([up]id (\\d+)) .* \\(([\\w\\.]+)\\)$"; 
	private final Pattern intentPattern = Pattern.compile(intentRegex);  

	// regex pattern for the action string of an intent
//	private final Pattern actionPattern = Pattern.compile("act=([\\w\\.]+)");

	// regex pattern for the package name 
//	private final Pattern packagePattern = Pattern.compile("pkg=([\\w\\.]+)");

	// regex pattern for the flags from an intent
	private final Pattern flagsPattern = Pattern.compile("flg=0x(\\d+)");

	// regex pattern for the destination component of an intent
//	private final Pattern cmpPattern = Pattern.compile("cmp=([\\w\\./\\w]+)");

	// BufferedReader for reading the log
	private BufferedReader reader;
	
	// the starting part of a log message corresponding to an intent
	static String startingString;

	// the PID of the system_server process
	static int systemServerPID = -1;

	
	public AR_IntentSniffer() {
		String systemServerPidString = String.valueOf(AR_IntentSniffer.systemServerPID);
		int size = systemServerPidString.length();
		String spaces = "";
		if (size == 2) {
			spaces = "   ";
		}		
		else if (size == 3) {
			spaces = "  ";
		}
		else if (size == 4) {
			spaces = " ";
		}		
		AR_IntentSniffer.startingString = "I(" + spaces + systemServerPidString + ") START";		
	}
	
	// stat method to create the log output
	private static BufferedReader createReader() throws IOException {
		// command to start logcat
		String[] cmd = new String[] {
				"logcat", "-v", "process",
				"-b", "system", "-s",
				"ActivityManager:D", 
		};
		
		// execute the logcat command and get the buffered reader
		Process logcat2 = Runtime.getRuntime().exec(cmd);
		
		if (DEBUG)
			Log.d(TAG, "Logcat Sniffer Thread Started");
		
		return new BufferedReader(new InputStreamReader(logcat2.getInputStream()));
	}


	// static block where if the default intentRegex does not match to find the sending
	// of intents then it can be changed by adding an exception for a particular build
	static {	  		
		
		switch(AR_Constants.BUILD_FINGERPRINT) {	
		case "google/hammerhead/hammerhead:4.4.2/KOT49H/937116:user/release-keys" : {
			intentRegex = "^\\w\\(\\s*(\\d+)\\) START \\w+ \\{(.*)\\} from ([up]id (\\d+)) .* \\(([\\w\\.]+)\\)$";
			break;
		}
		case "google/hammerhead/hammerhead:6.0.1/MMB29S/2489379:user/release-keys" : {
			intentRegex = "^\\w\\(\\s*(\\d+)\\) START \\w+ \\{(.*)\\} from ([up]id (\\d+)) .* \\(([\\w\\.]+)\\)$";
			break;
		}	  
		default : {
			// the default regex works well on both of the builds shown above
			intentRegex = "^\\w\\(\\s*(\\d+)\\) START \\w+ \\{(.*)\\} from ([up]id (\\d+)) .* \\(([\\w\\.]+)\\)$";
			break;
		}
		}
	}

	// this method will pass back intent data for an intent that matches
	// the regex so it can be processed 
	public synchronized AR_IntentData nextIntent() throws IOException {
		// if the reader is null create obtain a new one
		if (reader == null) {
			Log.d(TAG, "Created new log reader");
			reader = AR_IntentSniffer.createReader();
		}
		String line = null;

		while ((line = reader.readLine()) != null) {		

			// see if the log message starts out the starting string of I( <system_server pid>) START
			if (AR_IntentSniffer.systemServerPID != -1 && !line.startsWith(AR_IntentSniffer.startingString))
				continue;
			
			// check to see if the log matches the intent regex	
			Matcher matcher = intentPattern.matcher(line);
			if (!matcher.matches()) continue;

			// the pid of the process that wrote the log message
			int authorPid = Integer.valueOf(matcher.group(1)); 

			// if the system_server PID has been identified and it was not the system_server
			// process that wrote the log message then ignore it.
			if (AR_IntentSniffer.systemServerPID != -1 && authorPid != AR_IntentSniffer.systemServerPID)
				continue;

			// we will either get the pid or the uid of the app that started the activity
			int sourcePid = -1;
			int uid = -1;      

			// get the pid or uid
			String pidOrUid = matcher.group(3);
			if (pidOrUid.charAt(0) == 'p')
				sourcePid = Integer.valueOf(matcher.group(4));
			else // starts with uid
				uid = Integer.valueOf(matcher.group(4));

			// intent data which is in-between the {}
			String data = matcher.group(2);

			// log tag
			String logtag = matcher.group(5);

			// action of the intent (if present)
			String action = "";
//			Matcher m = actionPattern.matcher(data);
//			if (m.find()) action = m.group(1);

			// the package name  
			String pkg = "";
//			m = packagePattern.matcher(data);
//			if (m.find()) pkg = m.group(1);

			// intent flags
			int flags = 0;
			Matcher m = flagsPattern.matcher(data);
			if (m.find()) flags = Integer.valueOf(m.group(1), 16);

			// we are only looking for intents that will start a new task
			// let flags set to zero slip by 
			if (flags == 0)
				continue;
			
			// if the intent will not create a new task, then continue
			if (!AR_DoSDefenseService.willIntentCreateNewTask(flags))
				continue;

//			// the component being launched
			String component = "";
//			m = cmpPattern.matcher(data);
//			if (m.find()) component = m.group(1);

//			// if the package name was not obtained, then get it from the component
//			if (pkg.isEmpty() && !component.isEmpty()) {
//				int slash = component.indexOf('/');
//				if (slash >= 0) {
//					pkg = component.substring(0, slash);
//				}
//			}      
			return new AR_IntentData(authorPid, sourcePid, uid, logtag, action, pkg, flags, component);    
		}

		// logcat has closed so ensure a new reader is started
		// on the next entry of the method
		reader = null;
		Log.w(TAG,  "Logcat Closed!");
		return null;
	}

	// method to close the reader
	public void close() throws IOException {
		if (reader != null) {
			reader.close();
		}
	}

	/* Examples of what intents looks like from various Android builds and devices.
	 * These data allow one to create a regex to identify the sending of intents from
	 * the app itself and also from the AlarmManager. The values are given in the 
	 * logcat -v process format.
	 * 
	 * AOSP 4.4.2 (Nexus 5) - google/hammerhead/hammerhead:4.4.2/KOT49H/937116:user/release-keys
	 *from app directly
	 * I( 2572) START u0 {act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] flg=0x10000000 cmp=com.kryptowire.reboot/.RebootMainActivity} from pid 11070  (ActivityManager)
	 * using AlarmManager
	 * I( 2572) Start proc com.kryptowire.reboot for activity com.kryptowire.reboot/.RebootMainActivity: pid=11081 uid=10412 gids={50412}  (ActivityManager)
	 * 
	 * Samsung 5.1.1 (Samsung S6 Edge)
	 * from app directly I( 2340) Start proc com.kryptowire.reboot for activity com.kryptowire.reboot/.RebootMainActivity: pid=5475 uid=10413 gids={50413}  (ActivityManager)
	 * 
	 * AOSP 6.0 (Nexus 5) google/hammerhead/hammerhead:6.0/MRA58K/2256973:user/release-keys
	 * from app directly
	 * I(  839) START u0 {act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] flg=0x10200000 pkg=com.google.android.talk cmp=com.google.android.talk/.SigningInActivity bnds=[246,1532][447,1784] (has extras)} from uid 10026 on display 0  (ActivityManager)
	 * 
	 */
}
