package com.kryptowire.antireboot;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;

public class AR_DisabledAppsList extends Activity {

	/* The Ar_DisabledAppsList will show the user the package names
	 * of the apps that have been disabled. The user can re-enable
	 * a disabled app by clicking on the package name.
	 */
	
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.disabled_apps_listview);

		// get the listview of disabled apps
		final ListView listview = (ListView) findViewById(R.id.listview);
				
		Bundle b = this.getIntent().getExtras();
		if (b != null) {

			// get the list of disabled package names
			final ArrayList<String> list = b.getStringArrayList(AR_Constants.DISABLED_APPS);
			if (list == null)
				return;

			// if there are not disabled apps, then inform the user
			if (list.size() == 0)
				Toast.makeText(this, "There are no disabled apps", Toast.LENGTH_LONG).show();
			
			// create class to hold the list 
			final StableArrayAdapter adapter = new StableArrayAdapter(this, android.R.layout.simple_list_item_1, list);
			
			// set the adapter
			listview.setAdapter(adapter);
			
			// enable fast scroll
			listview.setFastScrollEnabled(true);

			// handle when a user clicks on an item in a list
			listview.setOnItemClickListener(new AdapterView.OnItemClickListener() {

				@Override
				public void onItemClick(AdapterView<?> parent, final View view, int position, long id) {

					// get the package name of the app
					String packageName = listview.getItemAtPosition(position).toString();

					// re-enable the app
					AR_DisabledAppsList.this.enableApp(packageName);
					
					// remove it from the list of disabled apps
					AR_DisabledAppsList.this.removePakcageFromDisabledApps(packageName);					
					
					// show the user that the app has been re-enabled
					Toast.makeText(parent.getContext(), "Re-enabled: " + packageName, Toast.LENGTH_LONG).show();
					
					// remove the package name from the list
					adapter.remove(listview.getItemAtPosition(position).toString());
					
					// indicate that the list has changed
					adapter.notifyDataSetChanged();
				}
			});
		}
	}
	
	
	// this method will take the package name of an app as a parameter
	// and enable it via the command line. Not that this app is supposed
	// to be executed as a system app or be singed with the platform key
	public String enableApp(String packageName) {
		StringBuffer sb = new StringBuffer();
		String cmd[] = {"pm", "enable", packageName};		
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
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return sb.toString();
	}
	
	
	// will remove a package name from shared preferences when the app is reenabled
	public void removePakcageFromDisabledApps(String packageName) {
		HashSet<String> randomHashSet = new HashSet<String>(); // create a default return value
		SharedPreferences sp = this.getSharedPreferences(AR_Constants.DISABLED_APPS_SP_FILE, Context.MODE_PRIVATE); 		
		Set<String> results = sp.getStringSet(AR_Constants.PACKAGE_NAMES_DISABLED, randomHashSet);
		SharedPreferences.Editor spEditor = null;
		if (results != null) {
			if (results.contains(packageName)) {
				results.remove(packageName);												
				spEditor = sp.edit();
				spEditor.putStringSet(AR_Constants.PACKAGE_NAMES_DISABLED, results);
				spEditor.commit();								
			}			
		}
	}
	
	// a class to hold the array of package names for the adapter
	class StableArrayAdapter extends ArrayAdapter<String> {
		HashMap<String, Integer> mIdMap = new HashMap<String, Integer>();

		public StableArrayAdapter(Context context, int textViewResourceId, List<String> objects) {
			super(context, textViewResourceId, objects);
			for (int i = 0; i < objects.size(); ++i) {
				mIdMap.put(objects.get(i), i);
			}
		}

		@Override
		public long getItemId(int position) {
			String item = getItem(position);
			return mIdMap.get(item);
		}

		@Override
		public boolean hasStableIds() {
			return true;
		}
	}
}
