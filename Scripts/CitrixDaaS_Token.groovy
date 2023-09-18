import com.santaba.agent.util.script.ScriptCache
import groovy.json.JsonSlurper
import org.apache.http.client.utils.URIBuilder
import org.apache.http.message.BasicNameValuePair

// core http classes
import org.apache.http.auth.AuthScope
import org.apache.http.auth.Credentials
import org.apache.http.auth.NTCredentials
import org.apache.http.client.config.*
import org.apache.http.client.entity.*
import org.apache.http.client.methods.*
import org.apache.http.client.ServiceUnavailableRetryStrategy
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.entity.*
import org.apache.http.Header
import org.apache.http.HttpResponse
import org.apache.http.impl.client.BasicCredentialsProvider
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.impl.client.StandardHttpRequestRetryHandler
import org.apache.http.ssl.SSLContextBuilder
import org.apache.http.util.EntityUtils

// LM properties
def propDeviceId = hostProps.get('system.deviceId')
def propSystemHost = hostProps.get('system.hostname')
def propHost = hostProps.get('citrixdaas.host') ?: propSystemHost
def propClientId = hostProps.get('citrixdaas.api.id')
def propClientSecret = hostProps.get('citrixdaas.api.key')
def propCustomerId = hostProps.get('citrixdaas.customerid')

try
{
    def sessionToken = getSessionToken(propHost, propClientId, propClientSecret, propCustomerId)

    if (sessionToken == '')
    {
        println 'Error: Invalid session token.'
        return 2
    }
    else
    {
        def cache = ScriptCache.getCache()
        cache.set("CitrixDaasToken${propDeviceId}", sessionToken, 3600000)
    }

    return 0
}
catch (Exception e)
{
    println e
    return 1
}

String getSessionToken(String host, String clientId, String clientSecret, String customerId)
{
    def sessionToken = ''

    def postUriBuilder = new URIBuilder()
        .setScheme('https')
        .setHost(host)
        .setPath("/cctrustoauth2/${customerId}/tokens/clients")

    def postData = []
    postData.add(new BasicNameValuePair('grant_type', 'client_credentials'))
    postData.add(new BasicNameValuePair('client_id', clientId))
    postData.add(new BasicNameValuePair('client_secret', clientSecret))
    def postEntity = new UrlEncodedFormEntity(postData)

    def httpPost = new HttpPost(postUriBuilder.build())
    httpPost.setHeader('Accept', 'application/json')
    httpPost.setHeader('Content-Type', 'application/x-www-form-urlencoded')

    def postResponse = runRequest(httpPost, null, postEntity)

    if (postResponse.code == 200)
    {
        def jsonSlurper = new JsonSlurper()
        def jsonResponse = jsonSlurper.parseText(postResponse.body)
        sessionToken = jsonResponse.access_token
    }

    return sessionToken
}

Map runRequest(HttpRequestBase request, Credentials credentials=null, AbstractHttpEntity entity=null)
{
    if (request instanceof HttpGet != true)
    {
        request.setEntity(entity)
    }

    // http://docs.groovy-lang.org/docs/groovy-2.4.21/html/documentation/#_map_to_type_coercion
    // https://stackoverflow.com/questions/48541329/timeout-between-request-retries-apache-httpclient
    def waitPeriod = 0L
    def serviceRetry = [
        retryRequest: { response, executionCount, context ->
            // increase the wait for each try, here we would wait 3, 6 and 9 seconds
            waitPeriod += 3000L
            def statusCode = response.getStatusLine().getStatusCode()
            return executionCount <= 3 && (statusCode == 429 || statusCode == 500 || statusCode == 503)
        },
        getRetryInterval: {
            return waitPeriod
        }
    ] as ServiceUnavailableRetryStrategy

    // create an http client which retries for connection "I/O" errors and for certain http status codes
    HttpClientBuilder httpClientBuilder = HttpClients.custom()
        .setDefaultRequestConfig(RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build())
        .setRetryHandler(new StandardHttpRequestRetryHandler(3, false))
        .setServiceUnavailableRetryStrategy(serviceRetry)

    // allow self-signed certificates
    httpClientBuilder.setSSLContext(
        new SSLContextBuilder().loadTrustMaterial(null, TrustSelfSignedStrategy.INSTANCE).build()
    ).setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)

    if (credentials)
    {
        // attempt authentication with credentials supported by the BasicCredentialsProvider
        BasicCredentialsProvider credentialProvider = new BasicCredentialsProvider()
        credentialProvider.setCredentials(AuthScope.ANY, credentials)
        httpClientBuilder.setDefaultCredentialsProvider(credentialProvider)
    }

    CloseableHttpClient httpClient = httpClientBuilder.build()
    HttpResponse response = httpClient.execute(request)
    String responseBody = null

    if (response.getEntity())
    {
        // only attempt to convert the body to string if there is content
        responseBody = EntityUtils.toString(response.getEntity())
    }

    Integer code = response.getStatusLine().getStatusCode()
    List<Header> headers = response.getAllHeaders()

    def responseMap = [
        code: code,
        headers: headers,
        body: responseBody,
    ]

    httpClient.close()
    return responseMap
}
