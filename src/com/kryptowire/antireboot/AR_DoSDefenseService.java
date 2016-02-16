package com.kryptowire.antireboot;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningAppProcessInfo;
import android.app.ActivityManager.RunningTaskInfo;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;
import android.widget.Toast;

public class AR_DoSDefenseService extends Service {

	/* This class is a service that performs the monitoring
	 * of intents sent by third-party apps on the device. It
	 * starts threads to monitor the log, monitor the alarms
	 * used by an app, and a thread to decay the total amount
	 * of intents that have been sent by an app. If the intent
	 * threshold is crossed, then it will perform an enforcement
	 * action against the misbehaving app that is trying to soft
	 * reboot the device. This app should be run as a system app
	 * or be signed with the platform key so it can obtain the 
	 * appropriate permissions to disable, kill, or uninstall
	 * the apps that are trying to soft reboot the device by
	 * sending apps very rapidly.
	 *
	 * Two permission (DUMP and READ_LOGS) need to be granted to the application via
	 * ADB, although for full functionality the app needs to be either installed 
	 * as a systemapp or singed with the platform key. If the device is rooted, the
	 * system partition can be mounted as read-write with the command below.
	 * mount -o rw,remount,rw /system
	 * the app needs to be copied to the /system/priv-app directory. Then the
	 * apk needs to have its file permissions changed to 644.
	 * then remount system as read only and reboot
	 * mount -o ro,remount,ro /system
	 */

	// the log tag 
	private final static String TAG = AR_DoSDefenseService.class.getName();

	// stores the intent usage per app when rate-limiting is used
	private HashMap<String, IntentFreqContainer> intentDataPerApp;
	
	// stores the intent usage per app when total amount with decay is used
	private ConcurrentHashMap<String,Integer> intentDataPerAppTotal;
	
	// stores the number of alarms from the previous read, so the delta can be calculated
	private HashMap<String, Integer> alarmDataPerAppLastRead;
	
	// stores the pid to package name conversions for caching
	private static HashMap<Integer, String> pidToPackageName = new HashMap<Integer, String>();
	
	// stores the uid to package name conversions for caching
	private static HashMap<Integer, String> uidToPackageName = new HashMap<Integer, String>();
	
	// a hashset that contains package names that have breached the threshold
	private static HashSet<String> rebootThresholdReachedPackages;
	
	// the regex and pattern for identifying the source of activities from dumpsys activity activities
	static String activityRegex = "\\s*launchedFromUid=(\\d+) launchedFromPackage=(.*) userId=(\\d+)\\s*";
	private final Pattern activityPattern = Pattern.compile(activityRegex);
	
	// a hashmap with the package name as the key and the number of activities created as the value
	static HashMap<String,Integer> appActivityCount;

	// the number of seconds for the short time period
	private static final long SHORT_PERIOD_SECS = 30; 
	
	// the number of seconds for the long time period
	private static final long LONG_PERIOD_SECS = 120; 

	// a lock to enforce critical sections between modifying the data structure
	// that contains the current intents sent by a package
	private final Lock lock = new ReentrantLock();

	// the maximum number of intents that can be sent in the short time period
	// (not used since we are not going by rate)
	private static final int INTENT_MAX_COUNT_SHORT = 120;
	
	// the maximum number of intents that can be sent in the log time period
	// (not used since we are not going by rate)
	private static final int INTENT_MAX_COUNT_LONG = 480; 	

	// the short window rate (not used since we are not going by rate)
	private static final double SHORT_MAX_RATE = (double) INTENT_MAX_COUNT_SHORT / (double) SHORT_PERIOD_SECS;

	// the long window rate (not used since we are not going by rate)
	private static final double LONG_MAX_RATE = (double) INTENT_MAX_COUNT_LONG / (double) LONG_PERIOD_SECS;

	// write debugging information to the log if set to true
	private static final boolean DEBUG = AR_Constants.DEBUG;
	
	// the method to remove a task, i.e., ActivityManager.removeTask(.)
	private static Method mRemoveTask;
	
	 // the method to force stop a package ActivityManager.forceStopPackage(.)
	private static Method mForceStop;
	
	// static ActivityManager reference for threads to used
	private static ActivityManager mActivityManager;		
	
	// the regex and pattern for determining the number of times an alarm has been launched
	static String alarmRegex = "\\w*(.*) \\+(.*ms) running, (\\d+) wakeups:";	
	private final Pattern alarmPattern = Pattern.compile(alarmRegex);
	
	// a hastset containing the package name of system apps on the device
	static HashSet<String> systemApps;

	// the regex and pattern for identifying the recurrence interval of an alarm 
	static String repeatInterval = "\\s+ .* repeatInterval=(\\d+) .*";
	static final Pattern repeatIntervalPattern = Pattern.compile(repeatInterval);
	
	// a static reference to the package manager
	static PackageManager packMan;

	// regex and pattern to find the recurrence interval for the alarm
	static String elapsedAlarmRegex= "\\s*ELAPSED_WAKEUP #\\d+: Alarm\\{.* type \\d+ (.*)\\}\\s*";
	final Pattern elapsedAlarmPattern = Pattern.compile(elapsedAlarmRegex);

	// regex and pattern to find out the application component type from a PendingIntentRecord
	static String appComponentRegex = "\\s*operation=PendingIntent\\{.*: PendingIntentRecord\\{.* .* (.*)\\}\\}\\s*";
	final Pattern appComponentPattern = Pattern.compile(appComponentRegex);

	// the starting int of third-party apps
	private final static int APP_START_UID = 10000;	

	// load some methods reflectively
	static {

		Class<?> activityManagerClass = null;
		try {
			activityManagerClass = Class.forName("android.app.ActivityManager");
		} catch (ClassNotFoundException e) {e.printStackTrace();}
		try {
			// method signature changed in API Level 22
			if (AR_Constants.API_LEVEL > 21) {
				mRemoveTask = activityManagerClass.getMethod("removeTask", new Class[] { int.class });
				mRemoveTask.setAccessible(true);	
			}
			else {
				mRemoveTask = activityManagerClass.getMethod("removeTask", new Class[] { int.class, int.class });
				mRemoveTask.setAccessible(true);				
			}
		} catch (NoSuchMethodException e) {e.printStackTrace();}

		try {
			mForceStop = activityManagerClass.getMethod("forceStopPackage", new Class[] { String.class });
			mForceStop.setAccessible(true);
		} catch (NoSuchMethodException e) {e.printStackTrace();}
	}

	@Override
	public void onCreate() {
		Log.d(TAG, "onCreate");		

		// initialize the correct data structure for recording intent usage per
		// app depending on the current
		if (AR_Constants.ENFORCEMENT_MODE.equals(AR_Constants.INTENTS_RATE)) {
			intentDataPerApp = new HashMap<String, IntentFreqContainer>();
		}
		else if (AR_Constants.ENFORCEMENT_MODE.equals(AR_Constants.INTENTS_ABSOLUTE)) {
			intentDataPerAppTotal = new ConcurrentHashMap<String, Integer>(); 
			alarmDataPerAppLastRead = new HashMap<String, Integer>();
		}

		// write configuration parameters to the log on startup
		if (DEBUG)
			Log.d(TAG, "Parameters - intent threshold [" + AR_Constants.INTENT_THRESHOLD + "] - enforcement action [" + AR_Constants.ENFORCEMENT_ACTION + "] - enforcement mode [" + AR_Constants.ENFORCEMENT_MODE + "]");		
			
		// get the activity manager
		mActivityManager = (ActivityManager) this.getSystemService(Context.ACTIVITY_SERVICE);

		// get static reference to the PackageManager
		packMan = this.getPackageManager();

		// populate the fucking system apps
		if (AR_Constants.EXCLUDE_SYSTEM_APPS)    	
			systemApps = this.getSystemApps();

		// show user the package name of the app that last reboot the device if there was a soft reboot
		String lastRebootApp = this.getStringFromSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, AR_Constants.LAST_REBOOT_APP_SP_NAME, null);
		if (lastRebootApp != null) {				
			Toast.makeText(getApplicationContext(), "The last app to attempeted to soft reboot or soft rebooted your device was " + lastRebootApp, Toast.LENGTH_LONG).show();;				
			this.writeStringToSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, AR_Constants.LAST_REBOOT_APP_SP_NAME, null);	
		}
		
		// create the hash set for package names that try to soft reboot the device
		rebootThresholdReachedPackages = new HashSet<String>();
		
		// get the current PID of system_server
		AR_IntentSniffer.systemServerPID = this.getPidFromPackageName("system");
		Log.d(TAG, "PID of system_server - " + AR_IntentSniffer.systemServerPID);
		
		// check to see if the phone was just soft rebooted by an app, and if so
		// perform an enforcement action on the app 
		//this.performEnforcementActionOnRebootApp();
		this.launchPerformanEncforcementActionThread();
		
		// not effective for aggressive attacks
		//this.startActivityMonitoringThread();
		
		// start the log sniffer thread to look for intents
		this.startDosDefenseThread();

		// the alarm manager was made not effective for the attack in
		// api level 22 and up so only monitor is api level is less
		if (AR_Constants.API_LEVEL < 22)
			this.startAlarmLoggingThread();
		
		// we are examining the absolute amount of intents sent so we need to model 
		// the closing of activities by a user and decay the intents sent over time
		if (AR_Constants.ENFORCEMENT_MODE.equals(AR_Constants.INTENTS_ABSOLUTE)) {
			this.startIntentDecayThread();
		}		
	}
	
	// will start the thread that will decay the intent count of an app by
	// 1 every SINGLE_INTENT_DECAY_MILLISECONDS milliseconds
	private Thread startIntentDecayThread() {
		Thread thread = new Thread() {
			public void run() {				
				while (true) {
					try {
						// lock down the data structure that can be accessed in a different thread
						//lock.lock();						
						// iterate for each app that has sent an intent and decrement it by 1
						// every SINGLE_INTENT_DECAY_MILLISECONDS milliseconds
						for (String packageName : intentDataPerAppTotal.keySet()) {							
							Integer intentCount = intentDataPerAppTotal.get(packageName);
							if (intentCount == null)
								continue;
							int newIntVal = intentCount.intValue() - 1;
							if (newIntVal > 0) // store the new decayed value
								intentDataPerAppTotal.put(packageName, Integer.valueOf(newIntVal));
							else // the new value is 0, so remove it
								intentDataPerAppTotal.remove(packageName);
						}
					}
					catch (Exception e) {e.printStackTrace();}					
					finally {
						//lock.unlock();
					}
			    	try {
						Thread.sleep(AR_Constants.SINGLE_INTENT_DECAY_MILLISECONDS);
					} catch (InterruptedException e) {e.printStackTrace();}			    	
				}
			}
		};		
		thread.start();
		return thread;
	}
	
	// this method will examine and process the output of dumpsys activity activities
	// to get the current amount of activities started by a package name. This seeming
	// the best solution is not effective when the attack is aggressive since sometimes
	// the command will not return any data before the device soft reboot
	private Thread startActivityMonitoringThread() {
		
		appActivityCount = new HashMap<String, Integer>();
		
		Thread thread = new Thread() {
			public void run() {
				
				while (true) {
			    	String[] cmd = {"dumpsys", "activity", "activities"};
			    	BufferedReader reader = runCommandAndGetStrOutput(cmd);
			    	if (reader != null) {
						try {
							processActivityData(reader);
						} catch (IOException e1) {e1.printStackTrace();}			    		
			    	}
			    	try {
						Thread.sleep(AR_Constants.DUMPSYS_INTERVAL);
					} catch (InterruptedException e) {e.printStackTrace();}			    	
				}
			}
		};		
		thread.start();
		return thread;
	}
	

	// this method will process the output of the dumpsys activity activities
	// command to determine the number of activities started by each package
	// on the device
	private void processActivityData(BufferedReader reader) throws IOException {
		if (reader == null)
			return;
		String line = null;
		
		while ((line = reader.readLine()) != null) {

			Matcher activityMatcher = activityPattern.matcher(line);
			if (!activityMatcher.matches()) continue;

			String packageName = activityMatcher.group(2);

			// apps launched from shell user can be null
			if (packageName == null || packageName.equals("null"))
				continue;

			// exlcude the system apps if that is the prerogative 
			if (AR_Constants.EXCLUDE_SYSTEM_APPS) {
				if (systemApps.contains(packageName)) {
					continue;
				}
			}

			// increment the activity count for an app
			Integer count = appActivityCount.get(packageName);
			if (count == null) {
				appActivityCount.put(packageName, Integer.valueOf(1));
			}
			else {
				Integer newCount = count.intValue() + 1;  	    	  
				appActivityCount.put(packageName, newCount);
			}
		}

			
		// make sure we have something to process	
		if (appActivityCount.size() > 0) {
			Iterator<Map.Entry<String, Integer>> it = appActivityCount.entrySet().iterator();
			
			// iterate through each package to see if any has exceeded the intent threshold 
			while (it.hasNext()) {
				Map.Entry<String, Integer> pair = it.next();
				String packageName = pair.getKey();
				Integer count = pair.getValue();

				if (DEBUG)
					Log.d(TAG, "[" + packageName + "] - activity count=" + count);

				if (count > AR_Constants.INTENT_THRESHOLD) {

					if (DEBUG)
						Log.d(TAG, "[" + packageName + "] - has " + count + " concurrent open activities which is more than the threshold of " + AR_Constants.INTENT_THRESHOLD + "!");

					// record that the threshold has been breached
					boolean takeAction = this.rebootThresholdIntentReached(packageName);
					
					if (takeAction == true) {
						// perform a specific enforcement action since the threshold has been breached
						if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.KILL_APP))
							this.killAppAndRemoveTask(packageName, this.getPidFromPackageName(packageName));  
						else if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.UNINSTALL_APP))					
							this.uninstallApp(packageName);    	
						else if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.DISABLE_APP))
							this.disableApp(packageName);			
					}
				}
			}
		}		
		// clear the data structure for the next iteration
		appActivityCount.clear();    	
	}
	
	// this method processes the output from the dumpsys alarm command and
	// records the number of alarms that have occurred and records the
	// package name that started it
	public void processAlarmData(BufferedReader reader) throws IOException {
		if (reader  == null)
			return;
		String line = null;
		while ((line = reader.readLine()) != null) {
			boolean exclude = false;
			
			// check to see if we should examine the repeating interval
			// if so and it is too aggressive, the app will immediately
			// hit the threshold. we use three regexs here since the 
			// output has a clearly defined form
			if (AR_Constants.EXAMINE_REPEAT_INTERVAL) {
				Matcher riMatcher = elapsedAlarmPattern.matcher(line);
				if (riMatcher.matches()) {
					String packageName = riMatcher.group(1);
					if (AR_Constants.EXCLUDE_SYSTEM_APPS) {
						if (systemApps.contains(packageName))
							exclude = true;
					}
					if (exclude == false) {
						line = reader.readLine();							
						Matcher nextMatcher = repeatIntervalPattern.matcher(line);
						if (nextMatcher.matches()) {								
							int repeatInterval = Integer.valueOf(nextMatcher.group(1));							
							line = reader.readLine();								
							if (repeatInterval != 0 || repeatInterval > 1500) {
								Matcher lastMatcher = appComponentPattern.matcher(line);
								if (lastMatcher.matches()) {
									String type = lastMatcher.group(1);
									if (type.equalsIgnoreCase("startActivity")) {
										if (DEBUG)
											Log.d(TAG, "[" + packageName + "] - starting activities at " + repeatInterval + " ms is too fast!");

										// record that the app breached the threshold
										boolean takeAction = this.rebootThresholdIntentReached(packageName);
										
										if (takeAction == true) {
											// perform an enforcement action
											if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.KILL_APP))			
												this.killAppAndRemoveTask(packageName, this.getPidFromPackageName(packageName));  
											else if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.UNINSTALL_APP))
												this.uninstallApp(packageName);  
											else if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.DISABLE_APP))
												this.disableApp(packageName);											
										}
									}
									// processed a three line block so read in the next line
									line = reader.readLine();
								}									
							}
						}							
					}
				}
			}
			
			// filter out some lines
			if (!line.endsWith("wakeups:"))
				continue;
			
			// ensure they have the correct format
			Matcher matcher = alarmPattern.matcher(line);
			if (!matcher.matches()) 
				continue;

			//   com.kryptowire.reboot +1m41s739ms running, 576 wakeups:
			
			// package name that started the alarm
			String packageName = matcher.group(1).trim();
			
			// time since the alarm has been repeating
			String time = matcher.group(2); // +14ms
			
			// the alarm count for the specific alarm
			int alarmCount = Integer.valueOf(matcher.group(3));

			// if there are 0 alarms, skip it
			if (alarmCount == 0)
				continue;

			// if it is fast, sometimes it can add this string to the front
			// so cut it out
			if (packageName.startsWith("*ACTIVE* ")) {
				packageName = packageName.substring(9);
			}

			// 
			boolean tooFast = false;

			// exlcude the system apps if that is the prerogative 
			if (AR_Constants.EXCLUDE_SYSTEM_APPS) {
				if (systemApps.contains(packageName)) {
					continue;
				}
			}	    	  
			
			// handle the absolute count or the intent rate
			if (AR_Constants.ENFORCEMENT_MODE.equals(AR_Constants.INTENTS_ABSOLUTE)) {
				tooFast = this.isRateTooFastAlarms(alarmCount, 0, packageName);   
			}
			else if (AR_Constants.ENFORCEMENT_MODE.equals(AR_Constants.INTENTS_RATE)) {
				// split the string along non-numeric characters
				// it is generally of the form of 1m41s739ms
				String[] parts = time.split("\\D");
				int size = parts.length;
				
				// default to use when there overall time is less than a second
				int totalTimeSeconds = 1;
				if (size == 1) {
					tooFast = this.isRateTooFastAlarms(alarmCount, 1, packageName);
				}
				else {
					if (size == 2) {
						totalTimeSeconds = Integer.parseInt(parts[0]);  	    	  
					}
					else if (size == 3) {
						int minutesInSeconds = Integer.parseInt(parts[0]) * 60;
						int seconds = Integer.parseInt(parts[1]);
						totalTimeSeconds = minutesInSeconds + seconds;   
					}
					else if (size == 4) {
						int hoursInSeconds = Integer.parseInt(parts[0]) * 60 * 60;
						int minutesInSeconds = Integer.parseInt(parts[1]) * 60;
						int seconds = Integer.parseInt(parts[2]);
						totalTimeSeconds = hoursInSeconds + minutesInSeconds + seconds;
					}
					else if (size == 5) {
						int daysInSeconds = Integer.parseInt(parts[0]) * 60 * 60 * 24;
						int hoursInSeconds = Integer.parseInt(parts[1]) * 60 * 60;
						int minutesInSeconds = Integer.parseInt(parts[2]) * 60;
						int seconds = Integer.parseInt(parts[3]);
						totalTimeSeconds = daysInSeconds + hoursInSeconds + minutesInSeconds + seconds;
					}
					else if (size == 6) {
						int monthsInSeconds = Integer.parseInt(parts[0]) * 30 * 60 * 60 * 24;
						int daysInSeconds = Integer.parseInt(parts[1]) * 60 * 60 * 24;
						int hoursInSeconds = Integer.parseInt(parts[2]) * 60 * 60;
						int minutesInSeconds = Integer.parseInt(parts[3]) * 60;
						int seconds = Integer.parseInt(parts[4]);
						totalTimeSeconds = monthsInSeconds + daysInSeconds + hoursInSeconds + minutesInSeconds + seconds;	
					}
					
					// calculate the rate of intent sending and see if it exceeds the threshold
					tooFast = this.isRateTooFastAlarms(alarmCount, totalTimeSeconds, packageName);   					
				}
				
			}

			if (tooFast) {
				// the app has breached the threshold

				// record that the app breached the threshold
				boolean takeAction = this.rebootThresholdIntentReached(packageName);
				
				if (takeAction == true) {
					// perform an enforcement action on the attacking app
					if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.KILL_APP))
						this.killAppAndRemoveTask(packageName, this.getPidFromPackageName(packageName));  
					else if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.UNINSTALL_APP))
						this.uninstallApp(packageName);  
					else if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.DISABLE_APP))
						this.disableApp(packageName);					
				}
			}
		}	
	}
	
	// this method will take the package name of an app as a parameter
	// and disable it via the command line. Not that this app is supposed
	// to be executed as a system app
	public String disableApp(String packageName) {
		Log.d(TAG, "Disabling " + packageName);		
		StringBuffer sb = new StringBuffer();
		String cmd[] = {"pm", "disable", packageName};		
		Process p;
		try {
			p = Runtime.getRuntime().exec(cmd);
			
			BufferedReader reader = 
					new BufferedReader(new InputStreamReader(p.getInputStream()));
			String line = "";			
			while ((line = reader.readLine())!= null) {
				sb.append(line + "\n");
			}			
			p.waitFor();
			
			// record the package name of the app that has been disabled
			// so the user can re-enable it if desired
			this.addPackageNameToDisabledApps(packageName);			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return sb.toString();
	}

	// this method checks to see if the rate of alarms for a specific app 
	// exceeds the threshold for the particular mdoe it is operating as
	public boolean isRateTooFastAlarms(int intentCount, int seconds, String packageName) {
		try {
			//lock.lock();

			// check if absolute intent count is being used
			if (AR_Constants.ENFORCEMENT_MODE.equals(AR_Constants.INTENTS_ABSOLUTE)) {

				// get the intent count per package name from the last reading
				Integer lastRead = alarmDataPerAppLastRead.get(packageName);
				if (lastRead != null) {
					// this is not the first time it has detected alarms from this app

					// get the total number of intents from the app
					Integer totalIntents = intentDataPerAppTotal.get(packageName);
					if (totalIntents != null) {

						// add the new intents from the alarmManager to the total count
						int newTotalIntents = totalIntents.intValue() + (intentCount - lastRead.intValue());

						// store the total intents
						intentDataPerAppTotal.put(packageName, Integer.valueOf(newTotalIntents));

						// update the last reading from AlarmManager
						alarmDataPerAppLastRead.put(packageName, Integer.valueOf(intentCount));

						if (DEBUG)
							Log.d(TAG, "[" + packageName + "] - totalIntents=" + newTotalIntents + " - alarm");
						if (newTotalIntents > AR_Constants.INTENT_THRESHOLD)
							return true;
						else
							return false;
					}
					else {
						// should not be null but check anyways        				

						// get the last reading
						int newTotalIntents = intentCount - lastRead.intValue();   

						// set the alarmManager as the total intent count
						intentDataPerAppTotal.put(packageName, Integer.valueOf(newTotalIntents));

						// update the last reading from AlarmManager
						alarmDataPerAppLastRead.put(packageName, Integer.valueOf(intentCount));     					
						if (DEBUG)
							Log.d(TAG, "[" + packageName + "] - totalIntents=" + newTotalIntents + " - alarm");

						if (newTotalIntents > AR_Constants.INTENT_THRESHOLD)
							return true;
						else
							return false;
					}
				}
				else {
					//this is the first time it has detected alarms from this app   

					int newIntentTotal = 0;
					
					// get the total intent count
					Integer totalIntents = intentDataPerAppTotal.get(packageName);
					if (totalIntents != null) {

						// update the last reading from AlarmManager
						alarmDataPerAppLastRead.put(packageName, Integer.valueOf(intentCount));

						// add the total intents to the count from AlarmManager
						newIntentTotal = totalIntents.intValue() + intentCount;

						// update the total number of intents
						intentDataPerAppTotal.put(packageName, Integer.valueOf(newIntentTotal));    				
					}
					else {
						// this is the first time the 

						intentDataPerAppTotal.put(packageName, Integer.valueOf(intentCount));
						alarmDataPerAppLastRead.put(packageName, Integer.valueOf(intentCount));  
						newIntentTotal = intentCount;
						
					}

					if (DEBUG)
						Log.d(TAG, "[" + packageName + "] - totalIntents=" + intentCount + " - alarm");
					
					if (newIntentTotal > AR_Constants.INTENT_THRESHOLD)
						return true;
					else
						return false;
				}
			}
			else if (AR_Constants.ENFORCEMENT_MODE.equals(AR_Constants.INTENTS_RATE)) {  

				IntentFreqContainer ifc = intentDataPerApp.get(packageName);
				if (ifc != null) {
					intentCount = intentCount + ifc.numIntentsSentLong;
				}

				double rate = (double) intentCount / (double) seconds;
				if (DEBUG) {
					Log.d(TAG, "[" + packageName + "] intentCount=" + intentCount + ", seconds=" + seconds + ", rate=" + rate + " - alarm");
				}

				if (rate > SHORT_MAX_RATE) { // SHORT_MAX_RATE is 1.5   		
					Log.d(TAG, "[" + packageName + "] rate of " + rate + " is too fast for short time window!");
					intentDataPerApp.remove(packageName);
					return true;
				}
				else if (rate > LONG_MAX_RATE) { // LONG_MAX_RATE is 0.5833333333333334   		
					Log.d(TAG, "[" + packageName + "] rate of " + rate + " is too fast for long time window!");
					return true;
				}    		
			}    		

		} finally {
			//lock.unlock();
		}
		return false;
	}


	// this method will obtain the package names of system
	// apps on the device and return them in a hashset
	HashSet<String> getSystemApps() {    	
		HashSet<String> systemApps = new HashSet<String>();
		List<PackageInfo> list = packMan.getInstalledPackages(0);
		for(PackageInfo pi : list) {
			ApplicationInfo ai = null;
			try {
				ai = packMan.getApplicationInfo(pi.packageName, 0);
			} catch (NameNotFoundException e) {
				continue;
			}
			if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) {
				systemApps.add(ai.packageName);          
			}
		}    	
		
		// some process names to add as well so they can be ignored
		systemApps.add("system");
		systemApps.add("system_server");
		systemApps.add("com.android.systemui");
		systemApps.add("com.android.shell");
		return systemApps;
	}

	// will remove a task for an app if it exists in the foreground 
	// will not restart the services of an app even if they returned
	// START_STICKY
	public boolean clearSpecificTask(String packageName) {
		if (DEBUG)
			Log.d(TAG, "clearSpecificTask - " + packageName);
		List<RunningTaskInfo> recents =  mActivityManager.getRunningTasks(30);
		if (recents == null)
			return false;
		for( int i=0; i < recents.size(); i++ ) {
			RunningTaskInfo rti = recents.get(i);
			String packN = rti.baseActivity.getPackageName();
			if (packN == null)
				continue;
			if (packN.equals(packageName)) {
				// a value of 1 for the second parameter will prevent the app from starting again
				boolean removed = removeTask(rti.id, 1);
				if (DEBUG)
					Log.d(TAG, "[" + packN + "] removed is - " + removed);
				return removed;
			}        		
		}
		return false;
	}

	// will return the PID of a process based on its package name
	public int getPidFromPackageName(String packageName) {
		if (packageName == null)
			return -1;		
		List<RunningAppProcessInfo> recents = mActivityManager.getRunningAppProcesses();
		for( int i=0; i < recents.size(); i++ ) {
			RunningAppProcessInfo rti = recents.get(i);
			if (packageName.equals(rti.processName))
				return rti.pid;
		}
		return -1;
	}

	// service lifecycle callback method. return start_sticky so the 
	// service will be respawned if it crashese or is killed
	public int onStartCommand(Intent intent, int flags, int startId) {
		Log.d(TAG, "onStartCommand");
		return Service.START_STICKY;
	}

	// the method will uninstall an app by the package name that is provided as
	// the parameter
	private void uninstallApp(String packageName) {
		Log.d(TAG, "Attempting to uninstall - " + packageName);
				
		// create AsyncTask to perform the uninstallation of the app
		AS_AppModificationContainer[] task = {new AS_AppModificationContainer("uninstall", null, packageName)}; 
		AR_AppControlTask dap = new AR_AppControlTask(this, packMan, task);
		dap.execute(new Object[0]);
	}
	
	// convenience method to kill an app. it will create a thread to
	// call the force stop the package and another thread to try
	// to clear the tasks of the app 10 times
	private void killAppAndRemoveTask(final String packageName, int pid) {
		Log.d(TAG, "killAppAndRemoveTask - " + packageName);

		Thread forceStop = new Thread() {
			public void run() {
				forceStopPackage(packageName);		
			}
		};
		forceStop.setPriority(Thread.MAX_PRIORITY);
		forceStop.start();
		
		Thread clearTask = new Thread() {
			public void run() {
				clearTaskXtimes(10, packageName);		
			}
		};
		clearTask.setPriority(Thread.MAX_PRIORITY);
		clearTask.start();
	}
	
	// this method will call the clear task method reflectively x times
	// for the packageName app
	public void clearTaskXtimes(int x, String packageName) {
		// then try to remove the task so it won't start up again
		for (int a = 0; a < 10; a++) {
			boolean cleared = this.clearSpecificTask(packageName);
			if (cleared)
				break;
		}
	}
	
	// will stop an app by package name. if the app has a service that returns START_STICKY, then
	// it will be restarted. Then the app will have to be killed again and then it cycles like this
	public void forceStopPackage(String packN) {
		if (DEBUG)
			Log.d(TAG, "force stop of package - " + packN);
		try {
			mForceStop.invoke(mActivityManager, packN);
		} catch (Exception ex) {
			Log.i(TAG, "Reflective force stop failed", ex);
		}
	}

	// calls the removeTask method reflectively given a task id and some
	// flags
	public boolean removeTask(int taskId, int flags) {
		if (DEBUG)
			Log.d(TAG, "removeTask - id=" + taskId + ", flags=" + flags);		
		try {
			
			if (AR_Constants.API_LEVEL > 21) {
				return (Boolean) mRemoveTask.invoke(mActivityManager, Integer.valueOf(taskId));
			}
			else {
				return (Boolean) mRemoveTask.invoke(mActivityManager, Integer.valueOf(taskId), Integer.valueOf(flags));	
			}
		} catch (Exception ex) {
			Log.i(TAG, "Reflective task removal failed", ex);
		}
		return false;
	}

	// standard method that needs to be here
	@Override
	public IBinder onBind(Intent intent) {
		return null;
	}

	// this method 
	@Override
	public void onTaskRemoved(Intent rootIntent) {
		Intent restartService = new Intent(getApplicationContext(), this.getClass());
		restartService.setPackage(getPackageName());
		PendingIntent restartServicePI = PendingIntent.getService(getApplicationContext(), 1, restartService, PendingIntent.FLAG_ONE_SHOT);

		AlarmManager alarmService = (AlarmManager) getApplicationContext().getSystemService(Context.ALARM_SERVICE);
		alarmService.set(AlarmManager.ELAPSED_REALTIME, SystemClock.elapsedRealtime() +100, restartServicePI);
	}

	// standard service lifecycle callback method
	@Override
	public void onDestroy() {
		super.onDestroy();
		if (DEBUG)
			Log.d(TAG, "onDestroy");
	}

	// class to store intent data for an app
	private static class IntentFreqContainer {
		long initialTimeStamp; // initial time stamp (when app started)
		long shortTimestamp; // a timestamp for the when short time interval started
		long longTimestamp; // a timestamp for the when long time interval started
		int numIntentsSentShort; // number of intents sent during the short interval
		int numIntentsSentLong; // number of intents sent during the long interval
		int totalIntentsSent; // the total number of intents sent

		IntentFreqContainer(long nanoTime, int numInitialIntents) {
			this.shortTimestamp = nanoTime;
			this.initialTimeStamp = nanoTime;
			this.longTimestamp = nanoTime;
			this.numIntentsSentShort = numInitialIntents;
			this.numIntentsSentLong = numInitialIntents;
		}

		// resets the intents sent for the short time interval and updates the timestamp for the short time interval
		void updateShortTimeAndResetNumTimes(long newTime) {
			this.shortTimestamp = newTime;
			this.numIntentsSentShort = 0;
		}		

		// resets the intents sent for the long time interval and updates the timestamp for the long time interval
		void updateLongTimeAndResetNumTimes(long newTime) {
			this.longTimestamp = newTime;
			this.numIntentsSentLong = 0;
		}

		// increments the number of intents sent by the app
		void addIntentsSent(int numIntents) {
			this.numIntentsSentShort += numIntents;
			this.numIntentsSentLong += numIntents;			
		}		
	}

	// this method will return true if the app is sending intents higher than the short and/or long threshold for intent usage
	private boolean isRateTooFast(String callingPackage, int intentsCount) throws RemoteException {

		try {
			//lock.lock();
			if (AR_Constants.ENFORCEMENT_MODE.equals(AR_Constants.INTENTS_ABSOLUTE)) {
				Integer numIntents = intentDataPerAppTotal.get(callingPackage);
				if (numIntents != null) {
					int newNumIntents = numIntents.intValue() + intentsCount;
					intentDataPerAppTotal.put(callingPackage, Integer.valueOf(newNumIntents));
					if (DEBUG)
						Log.d(TAG, "[" + callingPackage + "] - totalIntents=" + newNumIntents + " - direct");										
					if (newNumIntents > AR_Constants.INTENT_THRESHOLD) {
						intentDataPerAppTotal.remove(callingPackage);
						return true;
					}
					return false;
				}
				else { // first time calling
					intentDataPerAppTotal.put(callingPackage, Integer.valueOf(intentsCount));

					if (DEBUG)
						Log.d(TAG, "[" + callingPackage + "] - totalIntents=" + intentsCount + " - direct");

					if (intentsCount > AR_Constants.INTENT_THRESHOLD) {						
						intentDataPerAppTotal.remove(callingPackage);						
						return true;
					}				
					return false;	

				}
			}	
			else if (AR_Constants.ENFORCEMENT_MODE.equals(AR_Constants.INTENTS_RATE)) {
				long currentNano = System.nanoTime(); // get the current time
				IntentFreqContainer ifc = intentDataPerApp.get(callingPackage); // try to obtain the entry from the hash table
				if (ifc != null) { 
					// app has sent intents before
					double shortDeltaSecs = (double) ((currentNano - ifc.shortTimestamp) / 1e9); // the time between current time and the last short timestamp in seconds as a double
					double longDeltaSecs = (double) ((currentNano - ifc.longTimestamp ) / 1e9); // the time between current time and the last long timestamp in seconds as a double

					// general debug info
					if (DEBUG)
						Log.d(TAG, "[" + callingPackage + "] : short time delta [" + shortDeltaSecs + "] - number of intents in short time period [" + ifc.numIntentsSentShort + "] - long time delta [" + longDeltaSecs + "] - number of intents in long time period [" + ifc.numIntentsSentLong + "] - direct");

					// update the timestamps if necessary
					if (longDeltaSecs >= LONG_PERIOD_SECS)
						ifc.updateLongTimeAndResetNumTimes(currentNano);
					if (shortDeltaSecs >= SHORT_PERIOD_SECS)
						ifc.updateShortTimeAndResetNumTimes(currentNano);	

					// add the number of intents that the process is trying to send
					ifc.addIntentsSent(intentsCount); 

					// check if the intents sent over the longer time interval have been exceeded
					if (ifc.numIntentsSentLong > INTENT_MAX_COUNT_LONG) {
						if (DEBUG)
							Log.d(TAG, "[" + callingPackage +"] attempted to send " + ifc.numIntentsSentLong + " which is more than " + INTENT_MAX_COUNT_LONG + " per long period - direct");
						return true;
					}			

					// check if the intents sent over the shorter time interval have been exceeded
					if (ifc.numIntentsSentShort > INTENT_MAX_COUNT_SHORT) {
						if (DEBUG)
							Log.d(TAG, "[" + callingPackage +"] attempted to send " + ifc.numIntentsSentShort + " which is more than " + INTENT_MAX_COUNT_SHORT + " per short period - direct");
						return true;
					}			
					return false;
				}
				else { 
					// this is the first time that the app has sent an intent
					ifc = new IntentFreqContainer(currentNano, intentsCount);
					intentDataPerApp.put(callingPackage, ifc);			

					// check if they are sending more than the max on their first sending on an intent (e.g., sending 400 intents using startActivities(Intent[]))
					if (ifc.numIntentsSentShort > INTENT_MAX_COUNT_SHORT) {
						if (DEBUG)
							Log.d(TAG, "[" + callingPackage +"] attempted to send " + ifc.numIntentsSentShort + " which is more than " + INTENT_MAX_COUNT_SHORT + " per short period - direct");
						return true;
					}
					return false;
				}
			}						
		} finally {
			//lock.unlock();
		}



		return false;
	}

	// will return true is bit x is set in the integer value. Otherwise, it will return false
	private static boolean isBitSet(int value, int x) {		
		if ((value & (1L << x)) != 0) {
			return true;
		}
		return false;
	}

	// Returns true if the parameter is an intent with the FLAG_ACTIVITY_MULTIPLE_TASK
	// and FLAG_ACTIVITY_NEW_TASK flag set 
	static boolean willIntentCreateNewTask(int flags) {
		
		// if there are no flags set just return
		if (flags == 0)
			return false;
		
		// check for FLAG_ACTIVITY_MULTIPLE_TASK
		boolean multipleTask = AR_DoSDefenseService.isBitSet(flags, 27);
		
		// check for FLAG_ACTIVITY_NEW_TASK
		boolean newTask = AR_DoSDefenseService.isBitSet(flags, 28);
		
		// return true if both flags are present
		return multipleTask && newTask;			
	}

	// will take the uid of an app and return the package name
	private String uidToPackageName(int uid) {
		Integer uidInt = Integer.valueOf(uid);
		String packageName = uidToPackageName.get(uidInt);
		if (packageName != null)
			return packageName;		
		String[] packages = packMan.getPackagesForUid(uid);
		if (packages != null) {
			uidToPackageName.put(uidInt, packages[0]);			
			return packages[0];
		}
		return null;
	}

	// method to start the log sniffer thread
	private void startDosDefenseThread() {
		Thread thread = new Thread() {
			public void run() {
				sniffAndDefend();
			}
		};
		thread.setPriority(Thread.MAX_PRIORITY);
		thread.start();
	}

	// method to start the thread that examines the alarm
	// usage of apps by parsing the output of the 
	// dumpsys alarm command
	private void startAlarmLoggingThread() {
		Thread thread = new Thread() {
			public void run() {
				String[] cmd = {"dumpsys", "alarm"};
				while (true) {
					BufferedReader reader = runCommandAndGetStrOutput(cmd);
					try {
						processAlarmData(reader);
					} catch (IOException e1) {
						e1.printStackTrace();
					}	
					try {
						Thread.sleep(AR_Constants.DUMPSYS_INTERVAL);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}
		};
		//thread.setPriority(Thread.MAX_PRIORITY);
		thread.start();
	}


	// this method will examine the log entries that send intents
	private void sniffAndDefend() {
		// create the sniffer
		AR_IntentSniffer intentSniffer = new AR_IntentSniffer();		
		while (true) {
			try {

				AR_IntentData intentData = null;
				
				// process a sniffed intent from the log
				while ((intentData = intentSniffer.nextIntent()) != null) {

					String packageName = "";
					// if uid is -1 then we have the PID to resolve to a package name
					if (intentData.uid != -1 && intentData.uid < APP_START_UID)
						continue;

					// if no uid is provided, then use the pid to get the package name
					if (intentData.uid == -1)
						packageName = AR_DoSDefenseService.getPackageNameFromPid(intentData.sourcePid);
					else
						packageName = uidToPackageName(intentData.uid);
					
					// if we are not able to resolve the package name them skip it
					if (packageName == null)
						continue;
					
					// exlcude the system apps if that is the prerogative 
					if (AR_Constants.EXCLUDE_SYSTEM_APPS) {
						if (systemApps.contains(packageName)) {
							continue;
						}
					}

					// check rate, kill if offending
					boolean tooFast = isRateTooFast(packageName, 1);
					if (tooFast) {
						if (DEBUG) {
							Log.d(TAG,  "Too fast: uid= " + intentData.uid + ", pid=" + intentData.sourcePid + ", package name= " + packageName);
						}

						// record that the threshold has been reached by the app
						boolean takeAction = this.rebootThresholdIntentReached(packageName);						
						if (takeAction == true) {
							if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.KILL_APP))							
								this.killAppAndRemoveTask(packageName, intentData.sourcePid);  
							else if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.UNINSTALL_APP))
								this.uninstallApp(packageName);  
							else if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.DISABLE_APP))
								this.disableApp(packageName);							
						}
					}
				}

			} catch (IOException ex){
				Log.e(TAG,  ex.getMessage(), ex);

			} catch (RemoteException ex) {
				Log.e(TAG,  ex.getMessage(), ex);
			}
		}
	}
	
	// will record the package name of an intent that has reached its
	// threshold for sending intents
	public boolean rebootThresholdIntentReached(String packageName) {
		
		try {
			//lock.lock(); 
			// only record the app once
			if (rebootThresholdReachedPackages.contains(packageName)) {
				if (DEBUG)
					Log.d(TAG, "already recorded " + packageName + " for reboot threshold reached!");
				return false;
			}
			
			// add the package name to shared preferences for attack apps
			this.addPackageNameToRebootAttackApps(packageName);
			
			// keep track of the number of times the app has soft rebooted the device
			int numReboot = this.getIntFromSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, packageName, -1);
			if (numReboot == -1) {
				numReboot = 1;			
				// only save it if the threshold is at least 1 reboot			
				this.writeIntToSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, packageName, 1);
				if (DEBUG)
					Log.d(TAG, packageName + " has either attempted to soft reboot or soft rebooted the device 1 time");
			}
			else {
				numReboot++;			
				this.writeIntToSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, packageName, numReboot);
				if (DEBUG)
					Log.d(TAG, packageName + " has either attempted to soft reboot or soft rebooted device " + numReboot + " times");
			}
			
			// add the package name to apps that have rebooted the device					
			rebootThresholdReachedPackages.add(packageName);
			Log.d(TAG, "added " + packageName + " to apps that have reached the threshold");
					
			
			// record the pid of system_server
			if (AR_IntentSniffer.systemServerPID != -1)
				this.writeIntToSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, AR_Constants.SYSTEM_SERVER_PID, AR_IntentSniffer.systemServerPID);
			
			// only take action if the number of soft reboots is greater than the reboot threshold
			if (numReboot > AR_Constants.REBOOT_COUNT_THRESHOLD) {
				Log.d(TAG, "Reboot threshold count reached for " + packageName + " - current attempted soft reboot or actual soft reboot count=" + numReboot + " and soft reboot threshold=" + AR_Constants.REBOOT_COUNT_THRESHOLD);
				return true;
			}			
			else {
				Log.d(TAG, "Reboot threshold count not reached for " + packageName + " - current attempted soft reboot or actual soft reboot count=" + numReboot + " and soft reboot threshold=" + AR_Constants.REBOOT_COUNT_THRESHOLD);
				return false;
			}
		}
		catch (Exception e) {
			if (DEBUG)
				e.printStackTrace();
		}
		finally {
			//lock.unlock();
		}
		return false;
	}
	
	// will add the package name to shared preferences to indicate that
	// it has been disabled
	private void addPackageNameToDisabledApps(String packageName) {
		HashSet<String> randomHashSet = new HashSet<String>(); // create a default return value
		SharedPreferences sp = this.getSharedPreferences(AR_Constants.DISABLED_APPS_SP_FILE, Context.MODE_PRIVATE); 		
		Set<String> results = sp.getStringSet(AR_Constants.PACKAGE_NAMES_DISABLED, randomHashSet);
		SharedPreferences.Editor spEditor = null;
		if (results != null) {
			if (!results.contains(packageName)) {
				results.add(packageName);
				spEditor = sp.edit();
				spEditor.putStringSet(AR_Constants.PACKAGE_NAMES_DISABLED, results);
				//spEditor.commit();
				spEditor.apply();
			}			
		}
	}	
	
	// will store the package name of an reboot attack app in shared preferences
	public void addPackageNameToRebootAttackApps(String packageName) {
		HashSet<String> randomHashSet = new HashSet<String>(); // create a default return value
		SharedPreferences sp = this.getSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, Context.MODE_PRIVATE); 		
		Set<String> results = sp.getStringSet(AR_Constants.PACKAGE_NAMES_REBOOT_ATTACK, randomHashSet);
		SharedPreferences.Editor spEditor = null;
		if (results != null) {
			if (!results.contains(packageName)) {
				results.add(packageName);
				spEditor = sp.edit();
				spEditor.putStringSet(AR_Constants.PACKAGE_NAMES_REBOOT_ATTACK, results);
				//spEditor.commit();
				spEditor.apply();
			}			
		}
		
		// write out the last app that rebooted the device
		this.writeStringToSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, AR_Constants.LAST_REBOOT_APP_SP_NAME, packageName);
	}

	// will remove a package name of an app that has soft rebooted the device
	public void removePakcageFromRebootApps(String packageName) {
		HashSet<String> randomHashSet = new HashSet<String>(); // create a default return value
		SharedPreferences sp = this.getSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, Context.MODE_PRIVATE); 		
		Set<String> results = sp.getStringSet(AR_Constants.PACKAGE_NAMES_REBOOT_ATTACK, randomHashSet);
		SharedPreferences.Editor spEditor = null;
		if (results != null) {
			if (results.contains(packageName)) {
				results.remove(packageName);												
				spEditor = sp.edit();
				spEditor.putStringSet(AR_Constants.PACKAGE_NAMES_REBOOT_ATTACK, results);
				//spEditor.commit();
				spEditor.apply();
			}			
		}
		// reset the counter for the number of times that an app has soft rebooted the device	
		if (DEBUG)
			Log.d(TAG, "Resetting soft reboot counter to 0 for " + packageName);
		this.writeIntToSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, packageName, 0);
	}
	
	// a method to look for apps that need some punitive action for rebooting the device
	private void launchPerformanEncforcementActionThread() {
		Runnable r = new Runnable() {
			@Override
			public void run() {
				AR_DoSDefenseService.this.performEnforcementActionOnRebootApp();
			}			
		};
		Thread t = new Thread(r);
		t.start();		
	}
	
	
	
	// this is generally called on the next reboot of the device to uninstall, kill, or disable
	// the app that just soft rebooted the device
	public void performEnforcementActionOnRebootApp() {
		
		// handler to access main thread
		Handler handler = new Handler(Looper.getMainLooper());
		
		HashSet<String> randomHashSet = new HashSet<String>(); // create a default return value
		SharedPreferences sp = this.getSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, Context.MODE_PRIVATE); 		
		
		// get a set of package names that have soft rebooted the device
		Set<String> results = sp.getStringSet(AR_Constants.PACKAGE_NAMES_REBOOT_ATTACK, randomHashSet);
		if (results == null || results.size() == 0) // change to results.size == 0
			return;		
		
		// get the PID of system_server that was stored
		int previousSystemServerPid = this.getIntFromSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, AR_Constants.SYSTEM_SERVER_PID, -1);
	
		if (DEBUG)
			Log.d(TAG, "Current system_server PID [" + AR_IntentSniffer.systemServerPID + "] and previous system_server PID [" + previousSystemServerPid + "]");
		
		
		// we are trying to prevent the attack in real time so we will only check the system_server pid if the reboot count
		// before an enforcement action is taken. If we prevent the attack in real time then the system_server pid will
		// not increase. The system_server PID will change is there is a soft reboot so we detect that
		//if (AR_Constants.REBOOT_COUNT_THRESHOLD > 0 && systemServerPid == previousSystemServerPid && previousSystemServerPid != -1)	{
		if (AR_Constants.REBOOT_COUNT_THRESHOLD > 0 && AR_IntentSniffer.systemServerPID == previousSystemServerPid)	{
			if (DEBUG)
				Log.d(TAG, "The device did not soft reboot since the system since system_server PID is the same and reboot threshold is more than 0");			
			return;
		}

				
		// iterate through all apps that soft rebooted the device and perform 
		// an enforcement action on them
		for (String pn : results) {
			int numReboots = this.getIntFromSharedPreferences(AR_Constants.REBOOT_ATTACK_APPS_SP_FILE, pn, -1);
			final String packageName = pn;
			
			if (DEBUG)
				Log.d(TAG, "[" + pn + "] has a soft reboot count of " + numReboots);
			
			// check to see if they have rebooted the device enough times
			// to receive the enforcement action
			if (numReboots > AR_Constants.REBOOT_COUNT_THRESHOLD) {
				if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.UNINSTALL_APP)) {
					Log.d(TAG, "[" + pn + "] either attempted to soft reboot the device or soft rebooted the device " + numReboots + " time(s) and will be uninstalled");
					this.uninstallApp(pn);
					
					handler.post(new Runnable() {
						@Override
						public void run() {
							Toast.makeText(getApplicationContext(), "The application " + packageName + " has been uninstalled since it either attempted to soft reboot the device or soft rebooted the device!", Toast.LENGTH_LONG).show();
						}
					});
				}
				else if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.DISABLE_APP)) {
					Log.d(TAG, "[" + pn + "] either attempted to soft reboot the device or soft rebooted the device " + numReboots + " time(s) and will be disabled");
					this.disableApp(pn);
					
					handler.post(new Runnable() {
						@Override
						public void run() {
							Toast.makeText(getApplicationContext(), "The application " + packageName + " has been disabled since it either attempted to soft reboot the device or soft rebooted the device!", Toast.LENGTH_LONG).show();
						}
					});
				}
				else if (AR_Constants.ENFORCEMENT_ACTION.equals(AR_Constants.KILL_APP)) {
					Log.d(TAG, "[" + pn + "] either attempted to soft reboot the device or soft rebooted the device " + numReboots + " time(s) and will be killed");
					int pid = this.getPidFromPackageName(pn);
					this.killAppAndRemoveTask(pn, pid);
					
					handler.post(new Runnable() {
						@Override
						public void run() {
							Toast.makeText(getApplicationContext(), "The application " + packageName + " has been killed since it either attempted to soft reboot the device or soft rebooted the device!", Toast.LENGTH_LONG).show();
						}
					});
				}				
				
				// reset the counter from the app since it was installed
				// the user can install it again if they want
				this.removePakcageFromRebootApps(pn);
			}
			else {
				if (DEBUG)
					Log.d(TAG, "Soft reboot threshold for " + pn + " not reached. Soft reboot threshold=" + AR_Constants.REBOOT_COUNT_THRESHOLD + ", soft reboot count=" + numReboots);
			}
		}
	}
	
	// this method will write a name/value pair to the shared preferences. The first
	// parameter is name that the string value (second parameter) will be stored under.
	public void writeStringToSharedPreferences(String spFile, String spName, String value) {
		SharedPreferences sharedPref = this.getSharedPreferences(spFile, Context.MODE_PRIVATE);
		SharedPreferences.Editor sharedPrefEditor = sharedPref.edit();
		sharedPrefEditor.putString(spName, value);		
		//sharedPrefEditor.commit();
		sharedPrefEditor.apply();
	}

	// this method will obtain a string from the shared preferences that is named after
	// the string parameter. if it does not exist a value of defaultValue will be returned
	public String getStringFromSharedPreferences(String spFile, String spName, String defaultValue) {
		SharedPreferences sharedPref = this.getSharedPreferences(spFile, Context.MODE_PRIVATE);
		String ret2 = sharedPref.getString(spName, defaultValue);
		return ret2;		
	}
	
	
	// this method will provide a name (first parameter) and try to obtain its 
	// associated boolean value. if the name does not exist in the shared preferences
	// a default value of false will be returned.
	public int getIntFromSharedPreferences(String spFile, String spName, int defaultValue) {
		SharedPreferences sharedPref = this.getSharedPreferences(spFile, Context.MODE_PRIVATE);
		int ret2 = sharedPref.getInt(spName, defaultValue);
		return ret2;		
	}
	
	
	// this method will write a name/value pair to the shared preferences. The first
	// parameter is name that the boolean value (second parameter) will be stored under.
	public void writeIntToSharedPreferences(String spFile, String spName, int value) {
		SharedPreferences sharedPref = this.getSharedPreferences(spFile, Context.MODE_PRIVATE);
		SharedPreferences.Editor sharedPrefEditor = sharedPref.edit();
		sharedPrefEditor.putInt(spName, value);		
		//sharedPrefEditor.commit();
		sharedPrefEditor.apply();
	}
	
	// will take the PID as a parameter and return the corresponding
	// package name of the app that has that pid
	public static String getPackageNameFromPid(int pid) {
		Integer pidInt = Integer.valueOf(pid);		
		String packageName = pidToPackageName.get(pidInt);
		if (packageName != null)
			return packageName;
		for (RunningAppProcessInfo processInfo : mActivityManager.getRunningAppProcesses()){
			if(processInfo.pid == pid){
				pidToPackageName.put(pidInt, processInfo.processName);				
				return processInfo.processName;
			}
		}
		return packageName;	 		
	}

	// execute a command and return a buffered reader so the output
	// can be processed by another method
	public static BufferedReader runCommandAndGetStrOutput(String[] cmd) {
		Process p = null;
		try {
			p = Runtime.getRuntime().exec(cmd);
			return new BufferedReader(new InputStreamReader(p.getInputStream()));
		} catch (IOException e1) {
			e1.printStackTrace();
		} 
		return null;
	}

	// This class is just a container to pass an uninstall instruction to
	// uninstall an app from the device
	static class AS_AppModificationContainer {
		String instruction;
		String filePath;
		String packageName;

		AS_AppModificationContainer(String instruction, String filePath, String packageName) {
			this.instruction = instruction;
			this.filePath = filePath;
			this.packageName = packageName;
		}	

		public String toString() {
			StringBuilder sb = new StringBuilder();
			if (this.packageName != null && this.packageName.length() > 0) {
				sb.append("Package Name: " + this.packageName + "\n");
			}
			if (this.instruction != null && this.instruction.length() > 0) {
				sb.append("Instruction: " + this.instruction + "\n");
			}
			if (this.filePath != null && this.filePath.length() > 0) {
				sb.append("File Path: " + this.filePath + "\n");
			}
			return sb.toString();
		}
	}
}



