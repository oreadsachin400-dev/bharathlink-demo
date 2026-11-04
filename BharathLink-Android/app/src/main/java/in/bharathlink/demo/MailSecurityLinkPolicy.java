package in.bharathlink.demo;

import java.net.URI;

/**
 * Read-only TEST browser handoff. Never transfers Supabase JWT, WebView cookies,
 * device keys, email message identifiers or identity assertions.
 * Native trust and Android install/release remain blocked independently.
 */
public final class MailSecurityLinkPolicy {
    public static final String TEST_URL =
        "https://oreadsachin400-dev.github.io/bharathlink-demo/bharatmail-dkim-test/";

    private MailSecurityLinkPolicy() {}

    public static boolean isExactAllowedTestUrl(String input) {
        if (input == null || !TEST_URL.equals(input)) return false;
        try {
            URI url = new URI(input);
            return "https".equals(url.getScheme())
                && "oreadsachin400-dev.github.io".equals(url.getHost())
                && url.getPort() == -1
                && url.getRawUserInfo() == null
                && url.getRawQuery() == null
                && url.getRawFragment() == null
                && "/bharathlink-demo/bharatmail-dkim-test/".equals(url.getRawPath());
        } catch (Exception e) { return false; }
    }
}
