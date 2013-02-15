import com.google.api.client.auth.oauth.*;
import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.martiansoftware.jsap.JSAP;
import com.martiansoftware.jsap.JSAPException;
import com.martiansoftware.jsap.JSAPResult;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.ResourceBundle;

public class GAEOAuthClient
{

    private static final HttpTransport TRANSPORT = new NetHttpTransport();
    private static final ResourceBundle MESSAGES;

    private static JSAP JSAP;
    private static boolean VERBOSE = false;

    static
    {
        MESSAGES = ResourceBundle.getBundle("OAuthMessagesBundle");
    }

    private static JSAPResult parseArgs(final String[] args)
    {
        try
        {
            JSAP = new JSAP(Main.class.getResource(MESSAGES.getString("jsap-config")));
            final JSAPResult config = JSAP.parse(args);
            if (config.getBoolean("help") || !config.success())
            {
                System.out.format(MESSAGES.getString("jsap-usage"), MESSAGES.getString("jsap-jar-name"), JSAP.getUsage());
                System.out.println(JSAP.getHelp());

                if (!config.success())
                {
                    final Iterator i = config.getErrorMessageIterator();
                    while (i.hasNext())
                    {
                        System.out.println(i.next());
                    }
                    System.exit(2); //the traditional Unix exit status for command-line errors
                }
                else
                {
                    System.exit(0); // no errors
                }
            }
            return config;
        }
        catch (final IOException e)
        {
            throw new RuntimeException(e);
        }
        catch (final JSAPException e)
        {
            throw new RuntimeException(e);
        }
    }

    public static void main(final String[] args) throws IOException
    {
        final JSAPResult config = parseArgs(args);
        VERBOSE = config.getBoolean("verbose");
        final SecureResource resource = new SecureResource(config.getString("appid"), config.getString("resource"), config.getString("consumersecret"));
        // this signer will be used to sign all the requests in the "oauth dance"
        final File f = new File(System.getProperty("user.home") + "/." + resource.getConsumerKey() + ".json");
        if (!f.exists())
        {
            if (resource.getConsumerSecret() == null)
            {
                System.err.println("Could not load token file, please provide your Consumer Secret");
                System.out.format(MESSAGES.getString("oauth-usage") + System.getProperty("line.separator"), MESSAGES.getString("oauth-jar-name"), JSAP.getUsage());
                System.out.println(JSAP.getHelp());
                System.exit(2);
            }
            final OAuthCredentialsResponse accessTokenResponse = getAccessTokens(f, resource);
            writeCredentials(f, resource, accessTokenResponse);
        }
        makeRequest(f, resource);
    }

    private static Map<String, String> readCredentials(final File f)
    {
        try
        {
            final ObjectMapper mapper = new ObjectMapper();
            final Map<String, String> credentials = mapper.readValue(f, Map.class);
            System.out.println("credentials.toString() = " + credentials.toString());

            return credentials;
        }
        catch (final IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    private static OAuthCredentialsResponse getAccessTokens(final File f, final SecureResource resource)
    {
        try
        {
            final OAuthHmacSigner signer = new OAuthHmacSigner();
            signer.clientSharedSecret = resource.getConsumerSecret();

            // Step 1: Get a request token. This is a temporary token that is used for
            // having the user authorize an access token and to sign the request to obtain
            // said access token.
            final OAuthGetTemporaryToken requestToken = new OAuthGetTemporaryToken(resource.getRequestTokenURL());
            requestToken.consumerKey = resource.getConsumerKey();
            requestToken.transport = TRANSPORT;
            requestToken.signer = signer;

            final OAuthCredentialsResponse requestTokenResponse = requestToken.execute();

            System.out.println("Request Token:");
            System.out.println("    - oauth_token        = " + requestTokenResponse.token);
            System.out.println("    - oauth_token_secret = " + requestTokenResponse.tokenSecret);

            // updates signer's token shared secret
            signer.tokenSharedSecret = requestTokenResponse.tokenSecret;

            final OAuthAuthorizeTemporaryTokenUrl authorizeUrl = new OAuthAuthorizeTemporaryTokenUrl(resource.getAuthorizeURL());
            authorizeUrl.temporaryToken = requestTokenResponse.token;

            // After the user has granted access to you, the consumer, the provider will
            // redirect you to whatever URL you have told them to redirect to. You can
            // usually define this in the oauth_callback argument as well.
            String currentLine = "n";
            System.out.println("Launching the following link in your browser:\n" + authorizeUrl.build());

            openBrowser(new URL(authorizeUrl.build()));

            final InputStreamReader converter = new InputStreamReader(System.in);
            final BufferedReader in = new BufferedReader(converter);
            while (currentLine.equalsIgnoreCase("n"))
            {
                System.out.println("Have you authorized me? (y/n)");
                currentLine = in.readLine();
            }

            // Step 3: Once the consumer has redirected the user back to the oauth_callback
            // URL you can request the access token the user has approved. You use the
            // request token to sign this request. After this is done you throw away the
            // request token and use the access token returned. You should store this
            // access token somewhere safe, like a database, for future use.
            final OAuthGetAccessToken accessToken = new OAuthGetAccessToken(resource.getAccessTokenURL());
            accessToken.consumerKey = resource.getConsumerKey();
            accessToken.signer = signer;
            accessToken.transport = TRANSPORT;
            accessToken.temporaryToken = requestTokenResponse.token;

            final OAuthCredentialsResponse accessTokenResponse = accessToken.execute();
            System.out.println("Access Token:");
            System.out.println("    - oauth_token        = " + accessTokenResponse.token);
            System.out.println("    - oauth_token_secret = " + accessTokenResponse.tokenSecret);
            System.out.println("\nYou may now access protected resources using the access tokens above.");

            return accessTokenResponse;
        }
        catch (final IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    public static void openBrowser(final URL url)
    {
        final String osName = System.getProperty("os.name");
        try
        {
            if (osName.startsWith("Mac OS"))
            {
                final Class fileMgr = Class.forName("com.apple.eio.FileManager");
                final Method openURL = fileMgr.getDeclaredMethod("openURL", new Class[]{String.class});
                openURL.invoke(null, new Object[]{url.toString()});
            }
            else if (osName.startsWith("Windows"))
            {
                Runtime.getRuntime().exec("rundll32 url.dll,FileProtocolHandler " + url.toString());
            }
            else //assume Unix or Linux
            {
                final String[] browsers = {"chrome", "firefox", "opera", "konqueror", "epiphany", "mozilla", "netscape"};
                String browser = null;
                for (int count = 0; count < browsers.length && browser == null; count++)
                {
                    if (Runtime.getRuntime().exec(new String[]{"which", browsers[count]}).waitFor() == 0)
                    { browser = browsers[count]; }
                }
                if (browser == null)
                {
                    throw new RuntimeException("Could not find web browser");
                }
                else
                {
                    Runtime.getRuntime().exec(new String[]{browser, url.toString()});
                }
            }
        }
        catch (NoSuchMethodException e)
        {
            throw new RuntimeException(e);
        }
        catch (InterruptedException e)
        {
            throw new RuntimeException(e);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        catch (IllegalAccessException e)
        {
            throw new RuntimeException(e);
        }
        catch (InvocationTargetException e)
        {
            throw new RuntimeException(e);
        }
        catch (ClassNotFoundException e)
        {
            throw new RuntimeException(e);
        }
    }

    private static void writeCredentials(final File f, final SecureResource resource, final OAuthCredentialsResponse accessTokenResponse)
    {
        try
        {
            final Map<String, String> credentials = new HashMap<String, String>();
            credentials.put("consumer_key", resource.getConsumerKey());
            credentials.put("consumer_secret", resource.getConsumerSecret());
            credentials.put("access_token", accessTokenResponse.token);
            credentials.put("access_token_secret", accessTokenResponse.tokenSecret);
            final ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(f, credentials);
        }
        catch (final IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    private static void makeRequest(final File f, final SecureResource resource)
    {
        final Map<String, String> credentials = readCredentials(f);
        makeRequest(credentials, resource);
    }

    private static void makeRequest(final Map<String, String> credentials, final SecureResource resource)
    {// utilize accessToken to access protected resources
        try
        {
            final OAuthParameters parameters = new OAuthParameters();
            final OAuthHmacSigner signer = new OAuthHmacSigner();
            final ObjectMapper mapper = new ObjectMapper();
            signer.clientSharedSecret = credentials.get("consumer_secret");
            // updates signer's token shared secret
            signer.tokenSharedSecret = credentials.get("access_token_secret");
            parameters.consumerKey = credentials.get("consumer_key");
            parameters.token = credentials.get("access_token");
            parameters.signer = signer;

            final HttpRequestFactory factory = TRANSPORT.createRequestFactory(parameters);
            final GenericUrl url = new GenericUrl(resource.getProtectedResource());
            final HttpRequest req = factory.buildGetRequest(url);
            final HttpResponse resp = req.execute();
            System.out.println("Response Status Code: " + resp.getStatusCode());
            System.out.println("Response Body       : " + resp.parseAsString());
        }
        catch (final HttpResponseException e)
        {
            if (e.getStatusCode() == 401)
            {
                final File f = new File(System.getProperty("user.home") + "/." + resource.getConsumerKey() + ".json");
                final OAuthCredentialsResponse accessTokenResponse = getAccessTokens(f, resource);
                writeCredentials(f, resource, accessTokenResponse);
                makeRequest(f, resource);
            }
        }
        catch (final IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    public static class SecureResource
    {
        private final String appid;
        private final String resource;
        private final String consumerSecret;

        public SecureResource(final String appid, final String resource, final String consumerSecret)
        {
            this.appid = appid;
            this.resource = resource;
            this.consumerSecret = consumerSecret;
        }

        public String getConsumerKey()
        {
            return String.format("%s.appspot.com", this.appid);
        }

        public String getConsumerSecret()
        {
            return this.consumerSecret;
        }

        public String getProtectedResource()
        {
            return String.format("https://%s.appspot.com/%s", this.appid, this.resource);
        }

        public String getRequestTokenURL()
        {
            return String.format("https://%s.appspot.com/_ah/OAuthGetRequestToken", this.appid);
        }

        public String getAuthorizeURL()
        {
            return String.format("https://%s.appspot.com/_ah/OAuthAuthorizeToken", this.appid);
        }

        public String getAccessTokenURL()
        {
            return String.format("https://%s.appspot.com/_ah/OAuthGetAccessToken", this.appid);
        }
    }

}