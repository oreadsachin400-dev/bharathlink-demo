package in.bharathlink.demo;

import java.net.URI;

/** Source-only navigation gate for the untrusted TEST WebView.
 * Never opens non-HTTPS URI schemes or automatically launches iframes/redirects.
 * The exact internal Netlify host remains owned by the WebView. */
public final class ExternalNavigationPolicy {
    private static final String APP_HOST = "bharathlink-20-test.netlify.app";
    private ExternalNavigationPolicy() {}

    private static URI parsed(String raw) {
        if(raw == null || raw.isEmpty() || raw.length() > 2048) return null;
        for(int i=0; i<raw.length(); i++) {
            char c=raw.charAt(i);
            if(c <= 0x20 || c == 0x7f || c == '\\') return null;
        }
        try {
            URI uri=new URI(raw);
            if(!"https".equals(uri.getScheme()) || uri.getHost() == null ||
               uri.getRawUserInfo() != null || uri.getPort() != -1) return null;
            return uri;
        } catch(Exception e){ return null; }
    }

    public static boolean isInternalAppUrl(String url){
        URI uri=parsed(url);
        return uri != null && APP_HOST.equals(uri.getHost());
    }

    /** External HTTPS navigation is permitted only from a deliberate
     * foreground, main-frame tap. This does NOT claim that the URL is safe. */
    public static boolean mayOpenExternal(String url, boolean mainFrame, boolean hasGesture){
        if(!mainFrame || !hasGesture) return false;
        URI uri=parsed(url);
        return uri != null && uri.getRawFragment() == null &&
               !APP_HOST.equals(uri.getHost());
    }
}
