package com.kryptowire.antireboot;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class AR_Receiver extends BroadcastReceiver {

	/* This class is a BroadcastReceiver to start the service
	 * when it receives any broadcast intent that is sent to
	 * it. This class starts the service when the BOOT_COMPLETED
	 * broadcast intent is received by this class. In addition,
	 * the app also receives the android.hardware.usb.action.USB_STATE
	 * broadcast intent. 
	 */
	
	// boolean to only launch the service once
	static boolean serviceStarted = false;
	
	// the log tag
	private final static String TAG = AR_Receiver.class.getName();
	
	// if true, log messages will be written by the class
	private final static boolean DEBUG = AR_Constants.DEBUG;

	@Override
	public void onReceive(Context context, Intent intent) {
		
		// if the service has not been started then start it
		if (serviceStarted == false) {
			serviceStarted = true;
			Intent startServiceIntent = new Intent(context, AR_DoSDefenseService.class);
			context.startService(startServiceIntent);						
		}
		
		if (intent == null)
			return;
		Log.d(TAG, "The action is " + intent.getAction());
	}
}
