package com.kryptowire.antireboot;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

public class AR_MainA extends Activity {

	/* The AR_MainA class allows the user to re-enable apps that
	 * have been disabled since they either soft rebooted the 
	 * device or tried to soft reboot the device. The user
	 * can also restart the service.
	 */
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_ra__main);

		// launch the service as soon as the app is installed and run
		Intent startServiceIntent = new Intent(this, AR_DoSDefenseService.class);
		this.startService(startServiceIntent);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		getMenuInflater().inflate(R.menu.ra__main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			Toast.makeText(getApplicationContext(), "There are no Settings", Toast.LENGTH_SHORT).show();
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
	
	// will get the disabled apps and present them to the user
	// so they can re-enable any disabled apps
	public void disabledApps(View v) {		
		Set<String> disabledAppsSet = this.getDisabledApps();
		ArrayList<String> disabledAppsAL = new ArrayList<String>();
		
		// put the package names in an ArrayList
		for (String app : disabledAppsSet)
			disabledAppsAL.add(app);
		
		// pass the bundle to an activity so they can be listed
		Bundle b = new Bundle();
		b.putStringArrayList(AR_Constants.DISABLED_APPS, disabledAppsAL);
		Intent intent = new Intent(this, AR_DisabledAppsList.class);	
		intent.putExtras(b);
		this.startActivity(intent);	
	}
	
	// will return a set of package names that have been disabled
	private Set<String> getDisabledApps() {
		HashSet<String> randomHashSet = new HashSet<String>(); // create a default return value
		SharedPreferences sp = this.getSharedPreferences(AR_Constants.DISABLED_APPS_SP_FILE, Context.MODE_PRIVATE); 		
		Set<String> results = sp.getStringSet(AR_Constants.PACKAGE_NAMES_DISABLED, randomHashSet);		
		return results;
	}
	
	
	// method to restart the service
	public void restartService(View v) {
		Intent i = new Intent(this, AR_DoSDefenseService.class);
		this.stopService(i);		
		this.startService(i);
		Toast.makeText(getApplicationContext(), "Service has been restarted", Toast.LENGTH_SHORT).show();
	}
}
