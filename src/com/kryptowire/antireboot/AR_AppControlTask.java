package com.kryptowire.antireboot;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import com.kryptowire.antireboot.AR_DoSDefenseService.AS_AppModificationContainer;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.AsyncTask;
import android.util.Log;

public class AR_AppControlTask extends AsyncTask<Object[], Void, boolean[]> {

	/* The AR_AppControlTask class is used to install and uninstall applications
	 * on the device. In this context, it is only used to uninstall applications
	 * that have exceeded the intent threshold if the enforcement action is to
	 * uninstall the application as opposed to disabling it or killing it.
	 */

	// reference to the service in case the classloader is needed
	private AR_DoSDefenseService ds;  
	
	// debug flag for the class
	private static final boolean DEBUG = AR_Constants.DEBUG;
	
	// log tag
	private static final String TAG = AR_AppControlTask.class.getName();
	
	// a reference to the android.app.ApplicationPackageManager object
	private static PackageManager pm;
	
	// static reference to the android.app.ApplicationPackageManager class
	private static Class apmClass; 
	
	// static reference to the android.net.Uri class
	private static Class uriClass; 
	
	// static reference to the android.content.pm.IPackageInstallObserver class
	private static Class iPackageInstallObserverClass;
	
	// static reference to the android.content.pm.IPackageDeleteObserver class;
	private static Class iPackageDeleteObserverClass;
	
	// static reference to the String class
	private static Class stringClass = String.class;
	
	// static reference to the int class
	private static Class intClass = int.class;
	
	// the AppModificationTask object which this thread will fulfill
	private AS_AppModificationContainer[] tasks;  
	
	
	public AR_AppControlTask(AR_DoSDefenseService service, PackageManager pm, AS_AppModificationContainer[] tasks) {
		this.ds = service;
		if (AR_AppControlTask.pm == null)
			AR_AppControlTask.pm = pm;
		this.tasks = tasks;
	}
	
	// load static references for the Class objects which should load fine. If it fails, then use the
	// ClassLoader to get it in the init method
	static {
		try {			
			apmClass = Class.forName("android.app.ApplicationPackageManager");
		} catch (ClassNotFoundException e) {
			apmClass = null;
			if (DEBUG)
				e.printStackTrace();
		}
		
		try {
			uriClass = Class.forName("android.net.Uri");
		} catch (ClassNotFoundException e) {
			uriClass = null;
			if (DEBUG)
				e.printStackTrace();
		}
		
		try {
			iPackageInstallObserverClass = Class.forName("android.content.pm.IPackageInstallObserver");
		} catch (ClassNotFoundException e) {
			if (DEBUG)
				e.printStackTrace();
		}
		
		try {
			iPackageDeleteObserverClass = Class.forName("android.content.pm.IPackageDeleteObserver");
		} catch (ClassNotFoundException e) {
			if (DEBUG)
				e.printStackTrace();
		}
	}
	
	// the init method will load the appropriate classes and store them as static variables just in case it failed in 
	// the static block to initialize them
	private void init() {
		if (this.ds == null)
			return;
		ClassLoader cl = this.ds.getClassLoader();
		if (apmClass == null) {    		
    		try {
				apmClass = cl.loadClass("android.app.ApplicationPackageManager");
			} catch (ClassNotFoundException e) {
				if (DEBUG)
					e.printStackTrace();
			}
		}
		if (uriClass == null) {
    		try {
    			uriClass = cl.loadClass("android.net.Uri");
			} catch (ClassNotFoundException e) {
				if (DEBUG)
					e.printStackTrace();
			}
		}
		if (iPackageInstallObserverClass == null) {
    		try {
    			iPackageInstallObserverClass = cl.loadClass("android.content.pm.IPackageInstallObserver");
			} catch (ClassNotFoundException e) {
				if (DEBUG)
					e.printStackTrace();
			}
		}
		if (iPackageDeleteObserverClass == null) {
    		try {
    			iPackageDeleteObserverClass = cl.loadClass("android.content.pm.IPackageDeleteObserver");
			} catch (ClassNotFoundException e) {
				if (DEBUG)
					e.printStackTrace();
			}
		}
	}
	
    // method to uninstall an app reflectively using the package name
	// parameter
    public boolean uninstallAppReflection(String packageName) {
    	if (apmClass == null || iPackageDeleteObserverClass == null) {
    		return false;
    	}
    	if (DEBUG)
    		Log.d(TAG, "Uninstall task for " + packageName);
		try {
			//
			Class[] classes = {stringClass, iPackageDeleteObserverClass, intClass};
			// get the deletePackage(java.lang.String,android.content.pm.IPackageDeleteObserver,int) method
			Method targetMeth = apmClass.getDeclaredMethod("deletePackage", classes); 
			targetMeth.setAccessible(true); // set it accessible
			
			// create parameters
			Integer flags = Integer.valueOf(0);
			Object[] args = {packageName, null, flags};			
			
			try {
				// call the deletePackage method
				targetMeth.invoke(pm, args); 
				return true;
			} catch (IllegalAccessException e) {
				if (DEBUG)
					e.printStackTrace();
			} catch (IllegalArgumentException e) {
				if (DEBUG)
					e.printStackTrace();
			} catch (InvocationTargetException e) {
				if (DEBUG)
					e.printStackTrace();
			}
		} catch (Exception e) { 
			if (DEBUG)
				e.printStackTrace();
		}
		return false;
    }
	
	// method to install an app reflectively using the package name
    // parameter and the path to the apk to be installed
    public boolean installAppReflection(String packageName, String installPath) {
    	if (apmClass == null || iPackageInstallObserverClass == null) {
    		return false;
    	}
		try {
			Class[] classes = {uriClass, iPackageInstallObserverClass, intClass, stringClass};
			
			 // get the installPackage(android.net.Uri,android.content.pm.IPackageInstallObserver,int,java.lang.String) method
			Method targetMeth = apmClass.getDeclaredMethod("installPackage", classes);
			targetMeth.setAccessible(true); // set it accessible
			
			// create parameters
			Uri installUri = Uri.fromFile(new File(installPath));
			Integer flags = Integer.valueOf(0);
			Object[] args = {installUri, null, flags, null};						
			try {
				// call the installPackage method
				targetMeth.invoke(pm, args); 
				return true;
			} catch (IllegalAccessException e) {
				if (DEBUG)
					e.printStackTrace();
			} catch (IllegalArgumentException e) {
				if (DEBUG)
					e.printStackTrace();
			} catch (InvocationTargetException e) {
				if (DEBUG)
					e.printStackTrace();
			}
		} catch (Exception e) {
			if (DEBUG)
				e.printStackTrace();
		}
		return false;
    }
    
    // this method is executed once the AsyncTask is started. This method will process the 
    // the tasks that are passed to it to uninstall apps from the device
    @Override
    protected boolean[] doInBackground(Object[]... params) {
		this.init(); // initialize this object 
		int numTasks = tasks.length; // get the number of tasks		 
		boolean[] results = new boolean[numTasks]; // a boolean array to record the results of the tasks
		
		// iterate through the tasks and perform them
		for (int a = 0; a < tasks.length; a++) {
			AS_AppModificationContainer task = tasks[a]; // obtain the task
			if (task != null) { // make sure it is not null
				if (task.instruction.equals("install")) {
					// the task instruction is to install an application
					boolean res = this.installAppReflection(task.packageName, task.filePath);
					results[a] = res;
				}
				else if (task.instruction.equals("uninstall")) {
					// the task instruction is to uninstall an application
					boolean res = this.uninstallAppReflection(task.packageName);
					results[a] = res;
				}				
			}
		}
		return results; // return the results of the tasks
	}
}

