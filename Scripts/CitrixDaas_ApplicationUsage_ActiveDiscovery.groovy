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
def propUser = hostProps.get('citrixdaas.user')
def propPass = hostProps.get('citrixdaas.pass')
def propScheme = hostProps.get('citrixdaas.usehttps') ? 'https' : 'http'

def isCitrixCloud = propClientId && propClientSecret && propCustomerId
def sessionToken = ''
def ntCredentials = null

def lifecycleStateMap = [
    0: 'Active',
    1: 'Deleted',
    2: 'Requires Resolution',
    3: 'Stub'
]

def applicationTypeMap = [
    0: 'Hosted On Desktop',
    1: 'Installed On Client'
]

try
{
    def mainUriBuilder = new URIBuilder()
        .setScheme('https')
        .setHost(propHost)
        .setPath('/monitorodata/Applications')

    if (isCitrixCloud)
    {
        // get session token for Citrix Cloud API
        sessionToken = getCachedToken(propDeviceId) ?:
            getSessionToken(propHost, propClientId, propClientSecret, propCustomerId)

        if (sessionToken == '')
        {
            println 'Error: Invalid session token.'
            return 2
        }
    }
    else
    {
        // modify request for an on-prem delivery controller
        mainUriBuilder.setScheme(propScheme)
        mainUriBuilder.setPath('/Citrix/Monitor/OData/v4/Data/Applications')

        def credDomain = null
        if (propUser && propPass && propUser.contains('\\'))
        {
            credDomain = propUser.tokenize('\\')[0]
            credUser = propUser.tokenize('\\')[1]
        }
        else
        {
            throw new Exception(
                "The 'citrixdass.user' and 'pass' properties are required, the user must be in the DOMAIN\\User format."
            )
        }

        ntCredentials = new NTCredentials(credUser, propPass, propHost, credDomain)
    }

    def mainUri = mainUriBuilder.build()
    def mainResponse = runCitrixRequest(mainUri, sessionToken, propCustomerId, ntCredentials, isCitrixCloud)

    if (mainResponse.code == 429)
    {
        // rate limit response code
        println "Error: Bad response code (${mainResponse.code})."
        return 3
    }
    else if (mainResponse.code != 200)
    {
        println "Error: Bad response code (${mainResponse.code})."
        return 4
    }

    mainResponse.json.value.each { application ->
        def wildValue = application.Id
        def wildAlias = application.Name
        def adminFolder = application.AdminFolder.replace('/', '-') ?: 'Applications'

        def instanceProperties = [
            'citrixdaas.applicationtype' : applicationTypeMap.getOrDefault(application.ApplicationType, -1),
            'citrixdaas.enabled' : application.Enabled,
            'citrixdaas.adminfolder' : adminFolder,
            'citrixdaas.lifecyclestate' : lifecycleStateMap.getOrDefault(application.LifecycleState, -1)
        ]

        // Encode the instance property strings to escape any HTTP/URL special characters, the wild value/alias strings
        // appear to be encoded by LogicMontor automatically.
        instanceProperyStrings = instanceProperties.collect { property, value ->
            URLEncoder.encode(property, 'UTF-8') + '=' + URLEncoder.encode(value.toString(), 'UTF-8')
        }

        println "${wildValue}##${wildAlias}######${instanceProperyStrings.join('&')}"
    }

    return 0
}
catch (Exception e)
{
    println e
    return 1
}

String getCachedToken(String deviceId)
{
    def cache = ScriptCache.getCache()
    def cacheValue = cache.get("CitrixDaasToken${deviceId}")

    return cacheValue ?: ''
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

Map runCitrixRequest(URI uri, String token, String customerId, Credentials credentials, Boolean isCloud)
{
    def uriString = uri.toString()
    def responseMap = [
        code: null,
        json: null
    ]

    while (true)
    {
        def httpGet = new HttpGet(uriString)

        if (isCloud)
        {
            httpGet.addHeader('Authorization' , "CwsAuth Bearer=${token}")
            httpGet.addHeader('Citrix-CustomerId' , customerId)
        }

        def response = runRequest(httpGet, credentials)
        def jsonSlurper = new JsonSlurper()
        def json = jsonSlurper.parseText(response.body)

        if (responseMap.code == null)
        {
            // a null value in responseMap means this is the first page
            responseMap.code = response.code
            responseMap.json = json
        }
        else
        {
            // for additional pages append the "json.value" list to the existing list
            responseMap.code = response.code
            responseMap.json.value.addAll(json.value)
        }

        if (responseMap.code != 200)
        {
            // response is bad, stop now and return as we dont have the full result set
            return responseMap
        }

        if (json.get('@odata.nextLink') != null)
        {
            uriString = json['@odata.nextLink']
        }
        else
        {
            // no "nextLink" means all pages have been queried
            return responseMap
        }
    }
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
            // increase the wait for each try, here we would wait 10, 20 and 30 seconds
            waitPeriod += 10000L
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
