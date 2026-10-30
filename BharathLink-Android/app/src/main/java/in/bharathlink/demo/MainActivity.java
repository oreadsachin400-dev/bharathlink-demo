package in.bharathlink.demo;
import android.Manifest;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.PermissionRequest;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.net.Uri;
import android.content.Intent;
public class MainActivity extends Activity {
 private WebView web;
 private static final String HOME="https://bharathlink-20-test.netlify.app/";
 @Override public void onCreate(Bundle state) {
  super.onCreate(state); web=new WebView(this); setContentView(web);
  WebSettings s=web.getSettings(); s.setJavaScriptEnabled(true); s.setDomStorageEnabled(true);
  s.setAllowFileAccess(false); s.setAllowContentAccess(false); s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
  web.setWebViewClient(new WebViewClient(){
   @Override public boolean shouldOverrideUrlLoading(WebView view,android.webkit.WebResourceRequest request){
    Uri u=request.getUrl(); if("https".equals(u.getScheme()) && "bharathlink-20-test.netlify.app".equals(u.getHost())) return false;
    try {startActivity(new Intent(Intent.ACTION_VIEW,u));} catch(Exception ignored){} return true;
   }
  });
  web.setWebChromeClient(new WebChromeClient(){
   @Override public void onPermissionRequest(PermissionRequest request){
    if(!"https://bharathlink-20-test.netlify.app".equals(request.getOrigin().toString())){request.deny();return;}
    runOnUiThread(()->{
     boolean cam=checkSelfPermission(Manifest.permission.CAMERA)==android.content.pm.PackageManager.PERMISSION_GRANTED;
     boolean mic=checkSelfPermission(Manifest.permission.RECORD_AUDIO)==android.content.pm.PackageManager.PERMISSION_GRANTED;
     java.util.ArrayList<String> granted=new java.util.ArrayList<>();
     for(String r:request.getResources()){
      if(PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(r)&&cam)granted.add(r);
      if(PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(r)&&mic)granted.add(r);
     }
     if(granted.isEmpty())request.deny();else request.grant(granted.toArray(new String[0]));
    });
   }
  });
  if(state!=null)web.restoreState(state);else web.loadUrl(HOME);
 }
 @Override protected void onSaveInstanceState(Bundle out){web.saveState(out);super.onSaveInstanceState(out);}
 @Override public void onBackPressed(){if(web.canGoBack())web.goBack();else super.onBackPressed();}
}
