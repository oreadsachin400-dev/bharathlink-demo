package in.bharathlink.demo;

public final class MailSecurityLinkPolicyTest {
    private static void verdict(String url, boolean expected) {
        if (MailSecurityLinkPolicy.isExactAllowedTestUrl(url) != expected) {
            throw new AssertionError("Unsafe Mail Security URL acceptance: "+url);
        }
    }
    public static void main(String[] args) {
        String ok=MailSecurityLinkPolicy.TEST_URL;
        verdict(ok,true);
        verdict("http://oreadsachin400-dev.github.io/bharathlink-demo/bharatmail-dkim-test/",false);
        verdict("https://oreadsachin400-dev.github.io.evil.example/bharathlink-demo/bharatmail-dkim-test/",false);
        verdict("https://attacker@oreadsachin400-dev.github.io/bharathlink-demo/bharatmail-dkim-test/",false);
        verdict(ok+"?token=secret",false);
        verdict(ok+"#jwt",false);
        verdict(ok+"../mailbox/",false);
        verdict(ok.substring(0,ok.length()-1),false);
        verdict("javascript:alert(1)",false);
        verdict("file:///sdcard/secret",false);
        verdict("https://oreadsachin400-dev.github.io:443/bharathlink-demo/bharatmail-dkim-test/",false);
        verdict("HTTPS://oreadsachin400-dev.github.io/bharathlink-demo/bharatmail-dkim-test/",false);
        verdict(null,false);
        System.out.println("PASS: exact Android TEST URI; query, host spoof, userinfo and fragment rejected");
    }
}
