package com.kryptowire.antireboot;

import android.os.Build;

public class AR_Constants {
	
	/* A class to contain constants that are used throughout
	 * the application.
	 */
	
	// the api level of the device
	static final  int API_LEVEL = Build.VERSION.SDK_INT;
		
	// the build fingerprint of the device
	static final  String BUILD_FINGERPRINT = Build.FINGERPRINT;
	
	// the line character
	static final String NEWLINE = System.getProperty("line.separator");
	
	// if true, intents from system apps are not examined
	static final boolean EXCLUDE_SYSTEM_APPS = true;
	
	// uninstall the app action (possible ENFORCEMENT_ACTION)
	static final String UNINSTALL_APP = "uninstall app";
	
	// kill an app (possible ENFORCEMENT_ACTION)
	static final String KILL_APP = "kill app";
	
	// disabled the app (possible ENFORCEMENT_ACTION)
	static final String DISABLE_APP = "disable app";
	
	// the action to be taken when an app breaches the threshold
	static final String ENFORCEMENT_ACTION = DISABLE_APP;
	
	// examine the absolute amount of intents sent and decays them over time (possible ENFORCEMENT_MODE)
	static final String INTENTS_ABSOLUTE = "absolute";
	
	// examine the rate of intent sending (possible ENFORCEMENT_MODE)
	static final String INTENTS_RATE = "rate limit";

	// the mode that should be used for enforcement
	static final String ENFORCEMENT_MODE = INTENTS_ABSOLUTE;
	
	// the absolute number of intents that an app can have sent including
	// the decay before the enforcement action is taken
	static int INTENT_THRESHOLD = 200;
	
	// how many seconds it takes for an intent to decay for INTENTS_ABSOLUT
	static long SINGLE_INTENT_DECAY_MILLISECONDS = 2000;
	
	// the number of times an app can reboot the device before an enforcement action is taken
	// a value of 0 should be used for real time prevention. otherwise, the app will
	// wait for the device to soft reboot 
	static int REBOOT_COUNT_THRESHOLD = 0;
	
	// the interval in which dumpsys should run to collect the activity data from alarms
	static int DUMPSYS_INTERVAL = 500;
	
	// debug flag
	static boolean DEBUG = false;
	
	// shared preferences name for the String set containing apps that have done the reboot attack
	final static String PACKAGE_NAMES_REBOOT_ATTACK = "reboot_attack_apps";
	
	// shared preferences name for the String set containg apps that have been disabled
	final static String PACKAGE_NAMES_DISABLED = "disabled_apps";
	
	// the name that the dumpsys interval will be stored in using shared preferences
	static final String DUMPSYS_INTERVAL_SP_NAME = "dumpsys interval shared preferences name";
	
	// the name that the enforcement will be stored in using shared preferences
	static final String ENFORCMENT_ACTION_SP_NAME = "enforcement action shared preferences name";

	// the name that the enforcement will be stored in using shared preferences
	static final String INTENT_THRESHOLD_SP_NAME = "intent threshold shared preferences name";
	
	// the name the last app that rebooted the phone will be store under in shared preferences
	static final String LAST_REBOOT_APP_SP_NAME = "last app that rebooted device";
	
	// the name of the shared preferences file that will contain a set of package names of attacking apps
	static final String REBOOT_ATTACK_APPS_SP_FILE = "reboot_attack_sp";

	// the name of the shared preferences file that contains a set of package names of disabled apps 
	static final String DISABLED_APPS_SP_FILE = "disabled_apps_sp";
	
	// the name of the String to store the system_server pid in shared preferences
	static final String SYSTEM_SERVER_PID = "system_server pid";
	
	// whether of not to examine the repeat interval from alarms
	static final boolean EXAMINE_REPEAT_INTERVAL = true;
	
	// a constants for disabled apps
	static final String DISABLED_APPS = "disabled apps";
	
}
