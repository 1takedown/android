package com.bitwarden.authenticator.data.authenticator.manager.util

import app.cash.turbine.test
import com.bitwarden.authenticator.data.authenticator.datasource.sdk.AuthenticatorSdkSource
import com.bitwarden.authenticator.data.authenticator.manager.TotpCodeManagerImpl
import com.bitwarden.authenticator.data.authenticator.manager.model.VerificationCodeItem
import com.bitwarden.authenticator.data.authenticator.repository.model.AuthenticatorItem
import com.bitwarden.core.data.manager.dispatcher.FakeDispatcherManager
import com.bitwarden.core.data.util.asFailure
import com.bitwarden.core.data.util.asSuccess
import com.bitwarden.vault.TotpResponse
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class TotpCodeManagerTest {

    private val clock: Clock = Clock.fixed(
        Instant.parse("2023-10-27T12:00:00Z"),
        ZoneOffset.UTC,
    )
    private val authenticatorSdkSource: AuthenticatorSdkSource = mockk()
    private val dispatcherManager = FakeDispatcherManager()

    private val manager = TotpCodeManagerImpl(
        authenticatorSdkSource = authenticatorSdkSource,
        clock = clock,
        dispatcherManager = dispatcherManager,
    )

    @Test
    fun `getTotpCodesFlow should emit empty list when input list is empty`() =
        runTest {
            manager.getTotpCodesFlow(emptyList()).test {
                assertEquals(emptyList<VerificationCodeItem>(), awaitItem())
            }
        }

    @Test
    fun `getTotpCodesFlow should emit data if a valid value is passed in`() =
        runTest {
            val totp = "otpUri"
            val authenticatorItems = listOf(
                createMockAuthenticatorItem(number = 1, otpUri = totp),
            )
            val code = "123456"
            val nextCode = "654321"
            val totpResponse = TotpResponse(code = code, period = 30u)
            val nextTotpResponse = TotpResponse(code = nextCode, period = 30u)
            coEvery {
                authenticatorSdkSource.generateTotp(totp = totp, time = clock.instant())
            } returns totpResponse.asSuccess()
            coEvery {
                authenticatorSdkSource.generateTotp(
                    totp = totp,
                    time = clock.instant().plusSeconds(30),
                )
            } returns nextTotpResponse.asSuccess()

            val expected = createMockVerificationCodeItem(
                number = 1,
                code = code,
                nextCode = nextCode,
                issueTime = clock.instant().toEpochMilli(),
                timeLeftSeconds = 30,
            )

            manager.getTotpCodesFlow(authenticatorItems).test {
                assertEquals(listOf(expected), awaitItem())
            }
        }

    @Test
    fun `getTotpCodesFlow should emit item with null nextCode when next code generation fails`() =
        runTest {
            val totp = "otpUri"
            val authenticatorItems = listOf(
                createMockAuthenticatorItem(number = 1, otpUri = totp),
            )
            val code = "123456"
            val totpResponse = TotpResponse(code = code, period = 30u)
            coEvery {
                authenticatorSdkSource.generateTotp(totp = totp, time = clock.instant())
            } returns totpResponse.asSuccess()
            coEvery {
                authenticatorSdkSource.generateTotp(
                    totp = totp,
                    time = clock.instant().plusSeconds(30),
                )
            } returns Exception().asFailure()

            val expected = createMockVerificationCodeItem(
                number = 1,
                code = code,
                nextCode = null,
                issueTime = clock.instant().toEpochMilli(),
                timeLeftSeconds = 30,
            )

            manager.getTotpCodesFlow(authenticatorItems).test {
                assertEquals(listOf(expected), awaitItem())
            }
        }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `getTotpCodesFlow should keep countdowns in sync for items started at different times`() =
        runTest {
            // Start partway through a second so each item's flow begins at a different offset.
            val totpCodeManager =
                createVirtualTimeManager(Instant.parse("2023-10-27T12:00:00.400Z"))
            coEvery {
                authenticatorSdkSource.generateTotp(totp = any(), time = any())
            } returns TotpResponse(code = "123456", period = 30u).asSuccess()
            val item1 = createMockAuthenticatorItem(number = 1)
            val item2 = createMockAuthenticatorItem(number = 2)
            val testDispatcher = UnconfinedTestDispatcher(testScheduler)

            backgroundScope.launch(testDispatcher) {
                totpCodeManager.getTotpCodesFlow(listOf(item1)).collect()
            }
            advanceTimeBy(300.milliseconds)
            val codesFlow = totpCodeManager.getTotpCodesFlow(listOf(item1, item2))
            backgroundScope.launch(testDispatcher) { codesFlow.collect() }

            repeat(20) {
                advanceTimeBy(100.milliseconds)
                runCurrent()
                val timeLeftSeconds = codesFlow.value.map { it.timeLeftSeconds }
                assertEquals(2, timeLeftSeconds.size)
                assertEquals(timeLeftSeconds[0], timeLeftSeconds[1])
            }
        }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `getTotpCodesFlow should keep existing items counting after the item list changes`() =
        runTest {
            val totpCodeManager = createVirtualTimeManager(Instant.parse("2023-10-27T12:00:00Z"))
            coEvery {
                authenticatorSdkSource.generateTotp(totp = any(), time = any())
            } returns TotpResponse(code = "123456", period = 30u).asSuccess()
            val item1 = createMockAuthenticatorItem(number = 1)
            val item2 = createMockAuthenticatorItem(number = 2)
            val itemsFlow = MutableStateFlow(listOf(item1))
            var latestCodes = emptyList<VerificationCodeItem>()
            backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
                // Mirrors how the repository switches to a new list whenever the items change.
                itemsFlow
                    .flatMapLatest { totpCodeManager.getTotpCodesFlow(it) }
                    .collect { latestCodes = it }
            }

            itemsFlow.value = listOf(item1, item2)
            advanceTimeBy(6.seconds)
            runCurrent()

            assertEquals(listOf(24, 24), latestCodes.map { it.timeLeftSeconds })
        }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `getTotpCodesFlow should generate a new code when the period rolls over`() =
        listOf(30, 60).forEach { periodSeconds ->
            runTest {
                val period = periodSeconds.toLong()
                val boundary = Instant.parse("2023-10-27T12:00:00Z").plusSeconds(period)
                val start = boundary.minusMillis(600)
                val totpCodeManager = createVirtualTimeManager(start = start)
                val item = createMockAuthenticatorItem(number = 1)
                val generationTimes = stubTotpGeneration(item, periodSeconds, boundary)
                val codesFlow = totpCodeManager.getTotpCodesFlow(listOf(item))
                backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
                    codesFlow.collect()
                }

                assertEquals("123456", codesFlow.value.single().code)
                assertEquals("654321", codesFlow.value.single().nextCode)
                assertEquals(1, codesFlow.value.single().timeLeftSeconds)

                advanceTimeBy(600.milliseconds)
                runCurrent()
                assertEquals("654321", codesFlow.value.single().code)
                assertEquals("112233", codesFlow.value.single().nextCode)
                assertEquals(periodSeconds, codesFlow.value.single().timeLeftSeconds)

                // The new code is reused for the rest of its period.
                advanceTimeBy((periodSeconds - 1).seconds)
                runCurrent()
                assertEquals("654321", codesFlow.value.single().code)
                assertEquals(1, codesFlow.value.single().timeLeftSeconds)
                // Each generation also requests the next period's code.
                assertEquals(
                    listOf(
                        start,
                        start.plusSeconds(period),
                        boundary,
                        boundary.plusSeconds(period),
                    ),
                    generationTimes,
                )
            }
        }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `getTotpCodesFlow should count down from when a slow code is emitted`() =
        listOf(30, 60).forEach { periodSeconds ->
            runTest {
                val period = periodSeconds.toLong()
                val boundary = Instant.parse("2023-10-27T12:00:00Z").plusSeconds(period)
                // Generation starts 1.6 s before the boundary and finishes 0.8 s before it.
                val start = boundary.minusMillis(1600)
                val totpCodeManager = createVirtualTimeManager(start = start)
                val item = createMockAuthenticatorItem(number = 1)
                stubTotpGeneration(
                    item = item,
                    periodSeconds = periodSeconds,
                    boundary = boundary,
                    // The next-code request is the slow one.
                    slowTime = start.plusSeconds(period),
                )
                val codesFlow = totpCodeManager.getTotpCodesFlow(listOf(item))
                backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
                    codesFlow.collect()
                }

                advanceTimeBy(800.milliseconds)
                runCurrent()

                assertEquals("123456", codesFlow.value.single().code)
                assertEquals("654321", codesFlow.value.single().nextCode)
                assertEquals(1, codesFlow.value.single().timeLeftSeconds)
                assertEquals(start.toEpochMilli(), codesFlow.value.single().issueTime)
            }
        }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `getTotpCodesFlow should regenerate a code that expires during generation`() =
        listOf(30, 60).forEach { periodSeconds ->
            runTest {
                val period = periodSeconds.toLong()
                val boundary = Instant.parse("2023-10-27T12:00:00Z").plusSeconds(period)
                // Generation starts 0.6 s before the boundary and finishes 0.2 s after it.
                val start = boundary.minusMillis(600)
                val totpCodeManager = createVirtualTimeManager(start = start)
                val item = createMockAuthenticatorItem(number = 1)
                val generationTimes = stubTotpGeneration(
                    item = item,
                    periodSeconds = periodSeconds,
                    boundary = boundary,
                    // The next-code request is the slow one.
                    slowTime = start.plusSeconds(period),
                )
                val codesFlow = totpCodeManager.getTotpCodesFlow(listOf(item))
                val codes = mutableListOf<String?>()
                backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
                    codesFlow.collect { codes.add(it.singleOrNull()?.code) }
                }

                advanceTimeBy(800.milliseconds)
                runCurrent()

                // The stale code is never emitted.
                assertEquals(listOf(null, "654321"), codes)
                assertEquals("112233", codesFlow.value.single().nextCode)
                assertEquals(periodSeconds, codesFlow.value.single().timeLeftSeconds)
                val regenerationTime = start.plusMillis(800)
                assertEquals(
                    listOf(
                        start,
                        start.plusSeconds(period),
                        regenerationTime,
                        regenerationTime.plusSeconds(period),
                    ),
                    generationTimes,
                )
            }
        }

    @Test
    fun `getTotpCodesFlow should emit empty list if unable to generate auth code`() =
        runTest {
            val totp = "otpUri"
            val authenticatorItems = listOf(
                createMockAuthenticatorItem(number = 1, otpUri = totp),
            )
            coEvery {
                authenticatorSdkSource.generateTotp(totp = totp, time = clock.instant())
            } returns Exception().asFailure()

            manager.getTotpCodesFlow(authenticatorItems).test {
                assertEquals(
                    emptyList<VerificationCodeItem>(),
                    awaitItem(),
                )
            }
        }

    /**
     * Creates a [TotpCodeManagerImpl] whose clock and dispatcher follow this test's virtual time,
     * starting at [start].
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    private fun TestScope.createVirtualTimeManager(start: Instant): TotpCodeManagerImpl =
        TotpCodeManagerImpl(
            authenticatorSdkSource = authenticatorSdkSource,
            clock = mockk {
                every { instant() } answers { start.plusMillis(testScheduler.currentTime) }
                every { millis() } answers { start.toEpochMilli() + testScheduler.currentTime }
            },
            dispatcherManager = FakeDispatcherManager(
                unconfined = UnconfinedTestDispatcher(testScheduler),
            ),
        )

    /**
     * Stubs code generation for [item] with a [periodSeconds] period: "123456" before [boundary],
     * "654321" for the period after it and "112233" after that. A request for [slowTime] takes
     * 800 ms.
     *
     * Returns the times that codes were requested for.
     */
    private fun stubTotpGeneration(
        item: AuthenticatorItem,
        periodSeconds: Int,
        boundary: Instant,
        slowTime: Instant? = null,
    ): List<Instant> {
        val generationTimes = mutableListOf<Instant>()
        coEvery { authenticatorSdkSource.generateTotp(item.otpUri, any()) } coAnswers {
            val time = secondArg<Instant>()
            generationTimes.add(time)
            if (time == slowTime) delay(800.milliseconds)
            val code = when {
                time < boundary -> "123456"
                time < boundary.plusSeconds(periodSeconds.toLong()) -> "654321"
                else -> "112233"
            }
            TotpResponse(code = code, period = periodSeconds.toUInt()).asSuccess()
        }
        return generationTimes
    }
}
