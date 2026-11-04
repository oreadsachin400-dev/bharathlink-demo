package in.bharathlink.demo;

public final class ExternalNavigationPolicyTest {
    private static void verify(String url, boolean mainFrame, boolean gesture, boolean allowed) {
        boolean result = ExternalNavigationPolicy.mayOpenExternal(url,mainFrame,gesture);
        if (result != allowed) throw new AssertionError("External navigation gate mismatch: "+url);
    }
    private static void internal(String url,boolean wanted){
        if(ExternalNavigationPolicy.isInternalAppUrl(url)!=wanted)
            throw new AssertionError("Internal URL gate mismatch: "+url);
    }
    public static void main(String[] args){
        String home="https://bharathlink-20-test.netlify.app/";
        internal(home,true);
        internal(home+"mail?query=abc",true);
        internal(home+"#mail",true); // preserve SPA in-app hash navigation
        verify(home+"#mail",true,true,false);
        verify(home,true,true,false);
        verify("https://example.com/help",true,true,true);
        verify("https://example.com/help",false,true,false); // iframe
        verify("https://example.com/help",true,false,false); // redirect
        verify("http://example.com",true,true,false);
        verify("javascript:alert(1)",true,true,false);
        verify("file:///sdcard/user.db",true,true,false);
        verify("content://com.example.private/data",true,true,false);
        verify("intent://example.com/#Intent;end",true,true,false);
        verify("mailto:bank@example.com?body=secret",true,true,false);
        verify("tel:+911234567890",true,true,false);
        verify("data:text/html,hello",true,true,false);
        verify("https://user@example.com/path",true,true,false);
        verify("https://example.com:444/path",true,true,false);
        verify("https://example.com/#access_token=secret",true,true,false);
        verify("https://example.com/%0a",true,true,true);
        verify("https://example.com/x\\y",true,true,false);
        verify("https://example.com/x\npayload",true,true,false);
        verify("https://bharathlink-20-test.netlify.app.evil.example/",true,true,true);
        internal("https://bharathlink-20-test.netlify.app.evil.example/",false);
        internal("https://user@bharathlink-20-test.netlify.app/",false);
        verify(null,true,true,false);
        System.out.println("PASS: external navigation requires HTTPS, main-frame, gesture, no spoofed origin or unsafe scheme");
    }
}
