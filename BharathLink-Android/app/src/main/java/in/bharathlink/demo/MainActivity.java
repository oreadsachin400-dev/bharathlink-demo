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
import android.content.ActivityNotFoundException;
import android.app.AlertDialog;
import android.widget.Button;
import android.widget.LinearLayout;
public class MainActivity extends Activity {
 private WebView web;
 private static final String HOME="https://bharathlink-20-test.netlify.app/";
 @Override public void onCreate(Bundle state) {
  super.onCreate(state);
  LinearLayout shell=new LinearLayout(this);shell.setOrientation(LinearLayout.VERTICAL);
  Button mailSecurity=new Button(this);mailSecurity.setAllCaps(false);
  mailSecurity.setText("Mail Security TEST (external browser)");
  mailSecurity.setContentDescription("Open separate Mail Security TEST in external browser. No device verification.");
  shell.addView(mailSecurity,new LinearLayout.LayoutParams(
      LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT));
  web=new WebView(this);
  shell.addView(web,new LinearLayout.LayoutParams(
      LinearLayout.LayoutParams.MATCH_PARENT,0,1.0f));
  setContentView(shell);
  mailSecurity.setOnClickListener(v->new AlertDialog.Builder(this)
      .setTitle("Mail Security TEST only")
      .setMessage("Opens a separate website. Sign in there separately. No account, device, sender, organization or payment is verified by opening it.")
      .setNegativeButton("Cancel",(dialog,which)->dialog.dismiss())
      .setPositiveButton("Open TEST",(dialog,which)->{
        // Exact, pinned HTTPS endpoint. No token, key, identity or email data.
        if(!MailSecurityLinkPolicy.isExactAllowedTestUrl(MailSecurityLinkPolicy.TEST_URL))return;
        Intent go=new Intent(Intent.ACTION_VIEW,Uri.parse(MailSecurityLinkPolicy.TEST_URL));
        go.addCategory(Intent.CATEGORY_BROWSABLE);
        try{startActivity(go);}catch(ActivityNotFoundException ignored){}
      }).show());
  WebSettings s=web.getSettings(); s.setJavaScriptEnabled(true); s.setDomStorageEnabled(true);
  s.setAllowFileAccess(false); s.setAllowContentAccess(false); s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
  web.setWebViewClient(new WebViewClient(){
   @Override public boolean shouldOverrideUrlLoading(WebView view,android.webkit.WebResourceRequest request){
    Uri u=request.getUrl();
    String target=u==null?null:u.toString();
    if(ExternalNavigationPolicy.isInternalAppUrl(target))return false;
    if(!ExternalNavigationPolicy.mayOpenExternal(target,request.isForMainFrame(),request.hasGesture()))return true;
    try {
      Intent external=new Intent(Intent.ACTION_VIEW,u);
      external.addCategory(Intent.CATEGORY_BROWSABLE);
      startActivity(external);
    }catch(Exception ignored){}
    return true;
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
