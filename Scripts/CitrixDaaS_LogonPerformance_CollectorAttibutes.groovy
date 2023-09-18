import com.santaba.agent.util.script.ScriptCache
import groovy.json.JsonSlurper
import java.time.Duration
import java.time.format.DateTimeFormatter
import java.time.Instant
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

// limit the total number of sessions returned from the API, we don't care about logons that are too old
def propCollectDuration = hostProps.get('citrixdass.logonsearch')?.isInteger() ?
    hostProps.get('citrixdass.logonsearch').toInteger() : 240

// Tune the "Average" datapoint. By default returns the average over the last hour, will return a value when at least
// 3 sessions are found. During periods of low logon activity older sessions will be used to meet the 3 session
// requirement so a value is still returned.
propAverageDuration = hostProps.get('citrixdass.logonaveragesearch')?.isInteger() ?
    hostProps.get('citrixdass.logonaveragesearch').toInteger() : 60
propAverageThreshold = hostProps.get('citrixdass.logonaveragethreshold')?.isInteger() ?
    hostProps.get('citrixdass.logonaveragethreshold').toInteger() : 3

def isCitrixCloud = propClientId && propClientSecret && propCustomerId
def sessionToken = ''
def ntCredentials = null
def dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSX")
utcNow = ZonedDateTime.now(ZoneId.of('UTC'))
jsonDateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss[.SSS][.SS][.S]X")

try
{
    // limit the sessions collected, in a large environment this could be a lot, and we dont care about older logons
    def sessionStartDate = utcNow.minusMinutes(propCollectDuration)
    def sessionFormattedDate = sessionStartDate.format(dateFormat)

    def mainUriBuilder = new URIBuilder()
        .setScheme('https')
        .setHost(propHost)
        .setPath('/monitorodata/Sessions')
        .setParameter('$select', 'StartDate,LogOnDuration,EndDate')
        .setParameter(
            '$expand',
            'Machine($select=DesktopGroupId),Connections($select=LogOnStartDate,LogOnEndDate,BrokeringDuration,' +
            'VMStartStartDate,VMStartEndDate,HdxStartDate,HdxEndDate,AuthenticationDuration,GpoStartDate,GpoEndDate,' +
            'LogOnScriptsStartDate,LogOnScriptsEndDate,ProfileLoadStartDate,ProfileLoadEndDate,InteractiveStartDate,' +
            'InteractiveEndDate;$filter=IsReconnect eq false)'
        )
        .setParameter(
            '$filter', "LogOnDuration ne null and StartDate gt cast(${sessionFormattedDate}, Edm.DateTimeOffset)"
        )
        .setParameter('$orderby', 'StartDate desc') // return most recent sessions first

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
        mainUriBuilder.setPath('/Citrix/Monitor/OData/v4/Data/Sessions')

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

    // sort sessions from each desktop group into a List referenced by the desktopGroupId
    def sessionsByDesktopGroup = [:]
    mainResponse.json.value.each { session ->
        def desktopGroupId =  session.Machine.DesktopGroupId
        def sessionList = sessionsByDesktopGroup.get(desktopGroupId, [])
        sessionList << session
        sessionsByDesktopGroup[desktopGroupId] = sessionList
    }

    // calculate aggregate metrics for each desktop group and output the result
    sessionsByDesktopGroup.each { desktopGroupId, sessions ->
        setDurationKey('LogOn', sessions)
        setDurationKey('VMStart', sessions)
        setDurationKey('Hdx', sessions)
        setDurationKey('Gpo', sessions)
        setDurationKey('LogOnScripts', sessions)
        setDurationKey('ProfileLoad', sessions)
        setDurationKey('Interactive', sessions)

        outputConnectionMetrics('BrokeringDuration', sessions, desktopGroupId)
        outputConnectionMetrics('VMStartDuration', sessions, desktopGroupId)
        outputConnectionMetrics('HdxDuration', sessions, desktopGroupId)
        outputConnectionMetrics('AuthenticationDuration', sessions, desktopGroupId)
        outputConnectionMetrics('GpoDuration', sessions, desktopGroupId)
        outputConnectionMetrics('LogOnScriptsDuration', sessions, desktopGroupId)
        outputConnectionMetrics('ProfileLoadDuration', sessions, desktopGroupId)
        outputConnectionMetrics('InteractiveDuration', sessions, desktopGroupId)
        outputSessionMetrics(sessions, desktopGroupId)
        output('DebugTotalLogOns', sessions.size(), desktopGroupId)
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

void setDurationKey(String propertyPrefix, List sessions)
{
    sessions.each { session ->
        def startDateProperty = session.Connections[0][propertyPrefix + 'StartDate']
        def endDateProperty = session.Connections[0][propertyPrefix + 'EndDate']

        // calculate the duration between the "StartDate" and "EndDate" of the chosen connection property
        if (startDateProperty && endDateProperty)
        {
            def start = Instant.parse(startDateProperty)
            def end = Instant.parse(endDateProperty)
            def duration = Duration.between(start, end)
            // convert to milliseconds as existing duration properties (eg. BrokerDuration) are in millis
            session.Connections[0][propertyPrefix + 'Duration'] = duration.toMillis()
        }
        else
        {
            session.Connections[0][propertyPrefix + 'Duration'] = 0.0
        }
    }
}

void outputSessionMetrics(List sessions, String desktopGroupId)
{
    def sum = 0.0
    def max = 0.0
    def min = new BigDecimal(Integer.MAX_VALUE) // a large enough value to use for min()
    def count = 0.0
    def val = 0.0

    // find sessions within period chosen to calculate the average over
    def filteredSessions = sessions.findAll {
        utcNow.minusMinutes(propAverageDuration).isBefore(ZonedDateTime.parse(it['StartDate'], jsonDateFormat))
    }

    // If we dont have the minimum number of sessions within the "propAverageDuration" period then take the most recent
    // sessions from the larger "sessions" list. If the minimum number can't be found there then set an empty list.
    if (filteredSessions.size() < propAverageThreshold)
    {
        try
        {
            def end = propAverageThreshold - 1
            filteredSessions = sessions[0..end]
        }
        catch (IndexOutOfBoundsException e)
        {
            filteredSessions = []
        }
    }

    // check if the minimum threshold of sessions that must be found to calcuate the average from has been met
    if (filteredSessions.size() >= propAverageThreshold)
    {
        filteredSessions.each { session ->
            if (session['LogOnDuration'])
            {
                val = BigDecimal.valueOf(session['LogOnDuration'])
            }
            else
            {
                val = 0.0
            }

            sum += val
            max = Math.max(max, val)
            min = Math.min(min, val)
            count += 1
        }

        output('DebugRecentLogOns', filteredSessions.size(), desktopGroupId)
        output('LogOnDurationAverage', roundTo((sum / count) / 1000), desktopGroupId)
        output('LogOnDurationMaximum', roundTo(max / 1000), desktopGroupId)
        output('LogOnDurationMinimum', roundTo(min / 1000), desktopGroupId)
    }
}

void outputConnectionMetrics(String property, List sessions, String desktopGroupId)
{
    def sum = 0.0
    def count = 0.0
    def val = 0.0

    // find sessions within period chosen to calculate the average over
    def filteredSessions = sessions.findAll {
        utcNow.minusMinutes(propAverageDuration).isBefore(ZonedDateTime.parse(it['StartDate'], jsonDateFormat))
    }

    // If we dont have the minimum number of sessions within the "propRecentDuration" period then take the most recent
    // sessions from the larger "sessions" list. If the minimum number can't be found there then set an empty list.
    if (filteredSessions.size() < propAverageThreshold)
    {
        try
        {
            def end = propAverageThreshold - 1
            filteredSessions = sessions[0..end]
        }
        catch (IndexOutOfBoundsException e)
        {
            filteredSessions = []
        }
    }

    if (filteredSessions.size() >= propAverageThreshold)
    {
        filteredSessions.each { session ->
            // there is always a "logon" connection associated with a successfully created session (isReconnect=false)
            if (session.Connections[0][property])
            {
                val = BigDecimal.valueOf(session.Connections[0][property])
            }
            else
            {
                val = 0.0
            }

            sum += val
            count += 1
        }

        output("${property}Average", roundTo((sum / count) / 1000), desktopGroupId)
    }
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
