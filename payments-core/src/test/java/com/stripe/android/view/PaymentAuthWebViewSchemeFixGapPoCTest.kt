package com.stripe.android.view

import android.content.Intent
import android.net.Uri
import android.webkit.WebResourceRequest
import android.webkit.WebView
import androidx.test.core.app.ApplicationProvider
import com.google.common.truth.Truth.assertThat
import com.stripe.android.testing.FakeLogger
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.Test

/**
 * PoC for the fix-gap in commit 1be3556 ("Sanitize payment authentication
 * intent URLs", PR #14843): that fix added component=null / selector=null /
 * +CATEGORY_BROWSABLE to the `intent://` branch of
 * [PaymentAuthWebViewClient.shouldOverrideUrlLoading], but the custom-scheme
 * branch ~16 lines above it still launches a bare implicit ACTION_VIEW with
 * NO browsable category and NO scheme allowlist.
 *
 * Security property the fix intended (from its own changelog entry):
 * "Restricted intent URLs in payment authentication to browsable activity
 * resolution." This test proves that property is NOT applied to plain
 * custom-scheme URLs (e.g. pocnb://...) even though both branches exist in
 * the same function and launch the same class of target.
 *
 * Pinned analysis commit: 9ba4c822 (stripe-android master, 2026-10-23),
 * which contains fix 1be3556 and still carries the unfixed branch.
 */
@RunWith(RobolectricTestRunner::class)
class PaymentAuthWebViewSchemeFixGapPoCTest {
    private val isPageLoaded = MutableStateFlow(false)
    private val onAuthCompletedErrors = mutableListOf<Throwable>()
    private var activityFinished = false

    private val webView = WebView(ApplicationProvider.getApplicationContext())

    @Test
    fun customSchemeUrl_launchesImplicitViewIntent_withoutBrowsableCategory() {
        val captured = mutableListOf<Intent>()
        val webViewClient = createWebViewClient(activityStarter = captured::add)

        val url = "pocnb://steal?d=from_auth_webview"
        val overridden = webViewClient.shouldOverrideUrlLoading(webView, FakeWebResourceRequest(url))

        assertThat(overridden).isTrue()
        assertThat(captured).hasSize(1)

        val intent = captured.first()
        assertThat(intent.action).isEqualTo(Intent.ACTION_VIEW)
        assertThat(intent.dataString).isEqualTo(url)
        assertThat(intent.component).isNull()
        assertThat(intent.selector).isNull()
        // THE FIX-GAP: commit 1be3556 forces CATEGORY_BROWSABLE on the
        // intent:// branch so that only handlers which opted into browser
        // launches can be reached from web content. This sibling branch
        // never adds it, so NON-browsable handlers are still reachable.
        assertThat(intent.hasCategory(Intent.CATEGORY_BROWSABLE)).isFalse()

        // The launch is treated as a successful deep-link handoff, not an
        // error: auth does not complete and no failure is surfaced.
        assertThat(onAuthCompletedErrors).isEmpty()
        assertThat(activityFinished).isFalse()
    }

    @Test
    fun equivalentIntentSchemeUrl_addsBrowsableCategory() {
        val captured = mutableListOf<Intent>()
        val webViewClient = createWebViewClient(activityStarter = captured::add)

        // Same target as above, expressed the intent:// way - the branch
        // commit 1be3556 actually sanitized.
        val url = "intent://steal?d=from_auth_webview#Intent;scheme=pocnb;end"
        val overridden = webViewClient.shouldOverrideUrlLoading(webView, FakeWebResourceRequest(url))

        assertThat(overridden).isTrue()
        assertThat(captured).hasSize(1)

        val intent = captured.first()
        assertThat(intent.action).isEqualTo(Intent.ACTION_VIEW)
        assertThat(intent.dataString).isEqualTo("pocnb://steal?d=from_auth_webview")
        assertThat(intent.component).isNull()
        assertThat(intent.selector).isNull()
        // The fix's own behavior, reproduced: browsable IS enforced here.
        assertThat(intent.hasCategory(Intent.CATEGORY_BROWSABLE)).isTrue()

        assertThat(onAuthCompletedErrors).isEmpty()
        assertThat(activityFinished).isFalse()
    }

    @Test
    fun differential_sameDeepLinkTarget_browsableEnforcedOnlyOnIntentSchemeBranch() {
        val customSchemeIntent = captureLaunchedIntent("pocnb://steal?d=from_auth_webview")
        val intentSchemeIntent =
            captureLaunchedIntent("intent://steal?d=from_auth_webview#Intent;scheme=pocnb;end")

        // Identical handoff in every respect except the security category.
        assertThat(customSchemeIntent.action).isEqualTo(intentSchemeIntent.action)
        assertThat(customSchemeIntent.dataString).isEqualTo(intentSchemeIntent.dataString)
        assertThat(customSchemeIntent.component).isEqualTo(intentSchemeIntent.component)
        assertThat(customSchemeIntent.selector).isEqualTo(intentSchemeIntent.selector)

        // The one difference that matters: the fix's browsable restriction is
        // present on the intent:// branch and absent on the custom-scheme
        // branch of the SAME function.
        assertThat(intentSchemeIntent.hasCategory(Intent.CATEGORY_BROWSABLE)).isTrue()
        assertThat(customSchemeIntent.hasCategory(Intent.CATEGORY_BROWSABLE)).isFalse()
        assertThat(customSchemeIntent.categories.isNullOrEmpty()).isTrue()
    }

    private fun captureLaunchedIntent(url: String): Intent {
        val captured = mutableListOf<Intent>()
        val webViewClient = createWebViewClient(activityStarter = captured::add)
        val overridden = webViewClient.shouldOverrideUrlLoading(webView, FakeWebResourceRequest(url))
        assertThat(overridden).isTrue()
        assertThat(captured).hasSize(1)
        return captured.first()
    }

    private fun createWebViewClient(
        activityStarter: (Intent) -> Unit = {},
    ): PaymentAuthWebViewClient {
        return PaymentAuthWebViewClient(
            FakeLogger(),
            isPageLoaded,
            "pi_123_secret_456",
            null,
            activityStarter,
        ) { error ->
            error?.let(onAuthCompletedErrors::add)
            activityFinished = true
        }
    }

    private class FakeWebResourceRequest(
        private val url: String,
    ) : WebResourceRequest {
        override fun getUrl(): Uri = Uri.parse(url)
        override fun isForMainFrame(): Boolean = false
        override fun isRedirect(): Boolean = false
        override fun hasGesture(): Boolean = false
        override fun getMethod(): String = "GET"
        override fun getRequestHeaders(): Map<String, String> = emptyMap()
    }
}
