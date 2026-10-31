package com.bitwarden.authenticator.data.authenticator.manager

import com.bitwarden.authenticator.data.authenticator.datasource.sdk.AuthenticatorSdkSource
import com.bitwarden.authenticator.data.authenticator.manager.model.VerificationCodeItem
import com.bitwarden.authenticator.data.authenticator.repository.model.AuthenticatorItem
import com.bitwarden.core.data.manager.dispatcher.DispatcherManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.onCompletion
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import java.time.Clock
import java.time.Instant
import javax.inject.Inject
import kotlin.time.Duration.Companion.milliseconds

private const val ONE_SECOND_MILLISECOND = 1000L
private const val STOP_TIMEOUT_DELAY_MS = 5000L

/**
 * Primary implementation of [TotpCodeManager].
 *
 * This implementation uses per-item [StateFlow] caching to prevent flow recreation on each
 * subscribe, ensuring smooth UI updates when returning from background. The pattern mirrors
 * the Password Manager's [TotpCodeManagerImpl].
 */
class TotpCodeManagerImpl @Inject constructor(
    private val authenticatorSdkSource: AuthenticatorSdkSource,
    private val clock: Clock,
    private val dispatcherManager: DispatcherManager,
) : TotpCodeManager {

    private val unconfinedScope = CoroutineScope(dispatcherManager.unconfined)

    /**
     * Cache of per-item StateFlows to prevent recreation on each subscribe.
     * Key is the [AuthenticatorItem], value is the cached [StateFlow] for that item.
     */
    private val mutableItemVerificationCodeStateFlowMap =
        mutableMapOf<AuthenticatorItem, StateFlow<VerificationCodeItem?>>()

    override fun getTotpCodesFlow(
        itemList: List<AuthenticatorItem>,
    ): StateFlow<List<VerificationCodeItem>> {
        if (itemList.isEmpty()) {
            return MutableStateFlow(emptyList())
        }

        val stateFlows = itemList.map { getOrCreateItemStateFlow(it) }

        return combine(stateFlows) { results ->
            results.filterNotNull()
        }
            .stateIn(
                scope = unconfinedScope,
                started = SharingStarted.WhileSubscribed(),
                initialValue = emptyList(),
            )
    }

    /**
     * Gets an existing [StateFlow] for the given [item] or creates a new one if it doesn't exist.
     * Each item gets its own [CoroutineScope] to manage its lifecycle independently.
     */
    private fun getOrCreateItemStateFlow(
        item: AuthenticatorItem,
    ): StateFlow<VerificationCodeItem?> {
        return mutableItemVerificationCodeStateFlowMap.getOrPut(item) {
            // Define a per-item scope so that we can clear the Flow from the map when it is
            // no longer needed.
            val itemScope = CoroutineScope(dispatcherManager.unconfined)

            createVerificationCodeFlow(item)
                .onCompletion {
                    mutableItemVerificationCodeStateFlowMap.remove(item)
                    itemScope.cancel()
                }
                .stateIn(
                    scope = itemScope,
                    started = SharingStarted.WhileSubscribed(
                        stopTimeoutMillis = STOP_TIMEOUT_DELAY_MS,
                    ),
                    initialValue = null,
                )
        }
    }

    /**
     * Creates a flow that emits [VerificationCodeItem] updates every second for the given [item].
     */
    private fun createVerificationCodeFlow(
        item: AuthenticatorItem,
    ): Flow<VerificationCodeItem?> = flow {
        var verificationCodeItem: VerificationCodeItem? = null

        while (currentCoroutineContext().isActive) {
            val dateTime = clock.instant()
            val time = dateTime.epochSecond.toInt()

            if (verificationCodeItem == null || verificationCodeItem.isExpired(dateTime)) {
                // If the item is expired, or we haven't generated our first item,
                // generate a new code using the SDK:
                authenticatorSdkSource
                    .generateTotp(item.otpUri, dateTime)
                    .onSuccess { response ->
                        val nextCodeValue = authenticatorSdkSource
                            .generateTotp(
                                item.otpUri,
                                dateTime.plusSeconds(response.period.toLong()),
                            )
                            .getOrNull()
                            ?.code
                        verificationCodeItem = VerificationCodeItem(
                            code = response.code,
                            nextCode = nextCodeValue,
                            periodSeconds = response.period.toInt(),
                            timeLeftSeconds = response.period.toInt() -
                                (time % response.period.toInt()),
                            issueTime = dateTime.toEpochMilli(),
                            id = item.cipherId,
                            issuer = item.issuer,
                            label = item.label,
                            source = item.source,
                        )
                    }
                    .onFailure {
                        // We are assuming that our otp URIs can generate a valid code.
                        // If they can't, we'll just silently omit that code from the list.
                        emit(null)
                        return@flow
                    }
            }

            val currentItem = verificationCodeItem
            val emissionTime = clock.instant()
            if (currentItem == null || currentItem.isExpired(emissionTime)) {
                continue
            }
            verificationCodeItem = currentItem.copy(
                timeLeftSeconds = currentItem.periodSeconds -
                    (emissionTime.epochSecond % currentItem.periodSeconds).toInt(),
            )
            emit(verificationCodeItem)
            // Wait until the start of the next second
            delay((ONE_SECOND_MILLISECOND - clock.millis() % ONE_SECOND_MILLISECOND).milliseconds)
        }
    }
}

private fun VerificationCodeItem.isExpired(dateTime: Instant): Boolean =
    Instant.ofEpochMilli(issueTime).epochSecond / periodSeconds !=
        dateTime.epochSecond / periodSeconds
