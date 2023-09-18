import com.santaba.agent.util.script.ScriptCache
import groovy.json.JsonSlurper
import java.time.format.DateTimeFormatter
import java.time.ZonedDateTime
import java.time.ZoneId
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
def dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSX")
def utcNow = ZonedDateTime.now(ZoneId.of('UTC'))

try
{
    // make sure we get a ResourceUtilization entry, these are created every 5 mins
    def resourceStartDate = utcNow.minusMinutes(8)
    def resouceFormattedDate = resourceStartDate.format(dateFormat)

    def mainUriBuilder = new URIBuilder()
        .setScheme('https')
        .setHost(propHost)
        .setPath('/monitorodata/Machines')
        .setParameter(
            '$select',
            'Id,Name,IsAssigned,IsInMaintenanceMode,IsPendingUpdate,CurrentRegistrationState,LastDeregisteredCode,' +
            'CurrentPowerState,CurrentSessionCount,IsPreparing,FaultState'
        )
        .setParameter(
            '$expand',
            'CurrentLoadIndex($select=EffectiveLoadIndex,Cpu,Memory,Disk,Network,CreatedDate),' +
            'DesktopGroup($select=Id,Name),ResourceUtilization($select=PercentCpu,UsedMemory,TotalMemory,CreatedDate;' +
            "\$filter=CreatedDate gt cast(${resouceFormattedDate},Edm.DateTimeOffset))"
        )
        .setParameter('$filter', 'Name ne null and DesktopGroup ne null')

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
        mainUriBuilder.setPath('/Citrix/Monitor/OData/v4/Data/Machines')

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

    mainResponse.json.value.each { machine ->
        def wildValue = machine.Id

        output('IsAssigned', machine.IsAssigned, wildValue)
        output('IsInMaintenanceMode', machine.IsInMaintenanceMode, wildValue)
        output('IsPendingUpdate', machine.IsPendingUpdate, wildValue)
        output('CurrentRegistrationState', machine.CurrentRegistrationState, wildValue)
        output('LastDeregisteredCode', machine.LastDeregisteredCode, wildValue)
        output('CurrentPowerState', machine.CurrentPowerState, wildValue)
        output('CurrentSessionCount', machine.CurrentSessionCount, wildValue)
        output('IsPreparing', machine.IsPreparing, wildValue)
        output('FaultState', machine.FaultState, wildValue)

        // A load index of 0 means the machine is off or not fully initialized, CurrentLoadIndex can also be
        // null when a machine is off or has no sessions in certain Citrix versions.
        if (machine.CurrentLoadIndex?.EffectiveLoadIndex > 0)
        {
            output('EffectiveLoadIndex', machine.CurrentLoadIndex.EffectiveLoadIndex, wildValue)
            output('CpuLoadIndex', machine.CurrentLoadIndex.Cpu, wildValue)
            output('MemoryLoadIndex', machine.CurrentLoadIndex.Memory, wildValue)
            output('DiskLoadIndex', machine.CurrentLoadIndex.Disk, wildValue)
            output('NetworkLoadIndex', machine.CurrentLoadIndex.Network, wildValue)
        }
        else
        {
            output('EffectiveLoadIndex', 0, wildValue)
            output('CpuLoadIndex', 0, wildValue)
            output('MemoryLoadIndex', 0, wildValue)
            output('DiskLoadIndex', 0, wildValue)
            output('NetworkLoadIndex', 0, wildValue)
        }

        // no resource utilization data means the machine is off or not fully initialized
        if (machine.ResourceUtilization.size() > 0)
        {
            def percentCpu = BigDecimal.valueOf(machine.ResourceUtilization.last().PercentCpu)
            def usedMemory = BigDecimal.valueOf(machine.ResourceUtilization.last().UsedMemory)
            def totalMemory = BigDecimal.valueOf(machine.ResourceUtilization.last().TotalMemory)

            output('PercentCpu', roundTo(percentCpu), wildValue)
            output('UsedMemory', roundTo(usedMemory), wildValue)
            output('TotalMemory', roundTo(totalMemory), wildValue)
        }
    }

    return 0
}
catch (Exception e)
{
    println e
    return 1
}

BigDecimal roundTo(Number value)
{
    return BigDecimal.valueOf(value).setScale(2, BigDecimal.ROUND_HALF_UP).stripTrailingZeros()
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

void output(key, value, instanceId=null)
{
    if (value instanceof BigDecimal)
    {
        // make sure BigDecimal does not render to string with Scientific Notation
        value = value.toPlainString()
    }

    if (value instanceof Boolean)
    {
        value = value ? 1:0
    }

    if (instanceId)
    {
        println "${instanceId}.${key}=${value}"
    }
    else
    {
        println "${key}=${value}"
    }
}
