package com.digitalpetri.opcua.ecc.client

import com.github.ajalt.mordant.animation.progress.BlockingAnimator
import com.github.ajalt.mordant.animation.progress.animateOnThread
import com.github.ajalt.mordant.animation.progress.execute
import com.github.ajalt.mordant.animation.textAnimation
import com.github.ajalt.mordant.rendering.TextColors.brightBlue
import com.github.ajalt.mordant.rendering.TextColors.brightYellow
import com.github.ajalt.mordant.rendering.TextColors.green
import com.github.ajalt.mordant.rendering.TextColors.red
import com.github.ajalt.mordant.terminal.Terminal
import java.net.URI
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.collections.iterator
import kotlin.math.roundToInt
import org.eclipse.milo.opcua.stack.core.NodeIds
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy

private const val BAR_WIDTH = 28
private const val LOG_PROGRESS_INTERVAL_SECONDS = 5L
private const val INLINE_PROGRESS_INTERVAL_MILLIS = 125L
private const val MODE_WIDTH = 17
private const val POLICY_WIDTH = 34
private const val RULE_WIDTH = 64
private const val STATUS_WIDTH = 8
private const val TOKEN_WIDTH = 10
private const val CONNECT_WIDTH = 10
private val SPINNER_FRAMES = listOf("|", "/", "-", "\\")

/**
 * Renders the probe as terminal-first evidence.
 *
 * The output is organized around the questions an interoperability run needs to answer: what the
 * server advertised, what the client actually attempted, where failures happened, and whether a
 * negotiated session could read standard server values.
 */
internal class ClientTerminal(
    private val terminal: Terminal = Terminal(),
) {
  fun renderProbeStart(plan: ProbePlanPreview) {
    terminal.println(
        "${title("Probing")} ${targetLabel(plan.options.targetUrl)}: " +
            "${plan.entries.count { it.shouldAttempt }} attemptable combinations; " +
            "final summary prints when complete."
    )
    terminal.println()
  }

  fun startProbeProgress(plan: ProbePlanPreview): ProbeProgress {
    val attemptable = plan.entries.count { it.shouldAttempt }
    if (attemptable == 0) return NoProbeProgress

    val running = AtomicBoolean(true)
    val completed = AtomicInteger()
    val failures = AtomicInteger()

    if (!terminal.terminalInfo.outputInteractive && shouldUseLogProgress()) {
      return LoggingProbeProgress(
          terminal = terminal,
          total = attemptable,
          running = running,
          completed = completed,
          failures = failures,
      )
    }

    if (!terminal.terminalInfo.outputInteractive) {
      return InlineProbeProgress(
          terminal = terminal,
          total = attemptable,
          running = running,
          completed = completed,
          failures = failures,
      )
    }

    val tick = AtomicInteger()

    val animation =
        terminal
            .textAnimation<Unit> {
              val frame = SPINNER_FRAMES[tick.getAndIncrement() % SPINNER_FRAMES.size]

              progressLine(
                  title(frame),
                  completed.get(),
                  attemptable,
                  failureSuffix(failures.get()),
              )
            }
            .animateOnThread(
                fps = 8,
                finished = { !running.get() },
            )

    animation.refresh(refreshAll = true)
    val future = animation.execute()

    return AnimatedProbeProgress(
        running = running,
        completed = completed,
        failures = failures,
        animator = animation,
        future = future,
    )
  }

  fun renderProbeResult(summary: ProbeSummary) {
    val stats = ReportStats.from(summary)

    terminal.println(title("ECC Demo Client Probe"))
    terminal.println(rule())
    terminal.println(row("Target", targetLabel(summary.options.targetUrl)))
    terminal.println(row("Discovery", summary.options.targetUrl))
    terminal.println(row("Endpoints", "${summary.advertisedEndpointCount} advertised"))
    terminal.println(
        row(
            "Trust",
            if (summary.remoteCertificatesAutoTrusted) {
              "remote certificates auto-trusted"
            } else {
              "remote certificates validated"
            },
        )
    )
    terminal.println(row("Client PKI", summary.keyStorePath.toString()))
    terminal.println(row("Milo SDK", summary.miloSdkVersion))
    terminal.println(row("Milo stack", summary.miloStackVersion))
    terminal.println(rule())
    terminal.println(
        meter(
            "Read success",
            stats.readSuccess,
            stats.attempted,
            if (stats.failures == 0 && stats.readSuccess > 0) {
              successText("${stats.readSuccess}/${stats.attempted}")
            } else {
              warningText("${stats.readSuccess}/${stats.attempted}")
            },
        )
    )
    terminal.println(
        meter(
            "Failures",
            stats.failures,
            stats.attempted,
            if (stats.failures == 0) {
              successText("0/${stats.attempted}")
            } else {
              failureText("${stats.failures}/${stats.attempted}")
            },
        )
    )
    terminal.println(
        row(
            "Coverage",
            "${stats.advertised} advertised | ${stats.filtered} filtered | " +
                "${stats.notAdvertised} not advertised",
        )
    )
    terminal.println(row("Local gaps", localGaps(stats.localSupport)))
    terminal.println(
        row(
            "Attempts",
            "${stats.attempted} attempted | ${stats.readSuccess} reads ok | " +
                "${stats.failures} failed | ${stats.skipped} skipped",
        )
    )
    terminal.println(rule())
    terminal.println()

    renderResultsByCategory(summary.results)
    renderFailures(summary.results)
    renderNotAdvertised(summary.entries)
    renderStandardReads(summary.results)
    renderTiming(summary)
  }

  private fun renderResultsByCategory(results: List<ProbeAttemptResult>) {
    terminal.println(section("Results by Category"))

    val attempted = results.filter { it.attempted }
    if (attempted.isEmpty()) {
      terminal.println("  none")
      terminal.println()
      return
    }

    val groups = resultGroups(attempted)
    for (category in ResultCategory.entries) {
      val categoryResults = groups[category].orEmpty()
      if (categoryResults.isEmpty()) continue

      val sortedResults = sortedResults(categoryResults)
      val successes = sortedResults.count { it.readSucceeded }
      val failures = sortedResults.size - successes
      val failureText =
          if (failures > 0) {
            ", $failures failed"
          } else {
            ""
          }

      terminal.println(
          "  ${category.displayName} ($successes/${sortedResults.size} ok$failureText)"
      )
      terminal.println(
          "    " +
              fixed("STATUS", STATUS_WIDTH) +
              " " +
              fixed("POLICY", POLICY_WIDTH) +
              " " +
              fixed("MODE", MODE_WIDTH) +
              " " +
              fixed("TOKEN", TOKEN_WIDTH) +
              " " +
              fixedRight("CONNECT", CONNECT_WIDTH)
      )

      for (result in sortedResults) {
        terminal.println(resultLine(result))
      }
      terminal.println()
    }
  }

  private fun renderFailures(results: List<ProbeAttemptResult>) {
    terminal.println(section("Failures"))

    val failures = failureGroups(results)
    if (failures.isEmpty()) {
      terminal.println("  ${successText("none")}")
      terminal.println()
      return
    }

    for (failure in sortedFailures(failures)) {
      terminal.println(
          "  ${failureText("FAIL")} ${failure.value}x ${failure.key.category.displayName()} - " +
              "${failure.key.combo} - ${failure.key.message}"
      )
    }
    terminal.println()
  }

  private fun renderNotAdvertised(entries: List<ProbeEntry>) {
    terminal.println(section("Not Advertised By Server"))

    val groups = notAdvertisedGroups(entries)
    if (groups.isEmpty()) {
      terminal.println("  ${successText("none")}")
      terminal.println()
      return
    }

    terminal.println("  " + fixed("POLICY", POLICY_WIDTH) + " MISSING COMBINATIONS")
    for ((policy, missingEntries) in groups) {
      terminal.println("  ${fixed(policy, POLICY_WIDTH)} ${missingCombinations(missingEntries)}")
    }
    terminal.println()
  }

  private fun renderStandardReads(results: List<ProbeAttemptResult>) {
    val successes = results.filter { it.readValues != null }
    if (successes.isEmpty()) return

    terminal.println(section("Standard Reads"))
    val readsByState =
        successes.groupBy { result -> result.readValues?.serverState ?: "unknown" }.toSortedMap()

    for ((state, stateResults) in readsByState) {
      val latestCurrentTime =
          stateResults.mapNotNull { result -> result.readValues?.currentTime }.maxOrNull()
              ?: "unknown"
      terminal.println(
          "  $state observed on ${stateResults.size} successful reads; " +
              "latest currentTime=$latestCurrentTime"
      )
    }
    terminal.println()
  }

  private fun renderTiming(summary: ProbeSummary) {
    terminal.println(section("Timing"))

    val timings = summary.timings
    val attemptTimings = summary.results.mapNotNull { it.timing }
    val attempted = summary.results.count { it.attempted }
    val skipped = summary.results.size - attempted

    terminal.println("  Total        ${durationText(timings.total)}")
    if (attemptTimings.isEmpty()) {
      terminal.println(
          "  Attempts     none attempted | $skipped skipped | loop ${durationText(timings.attempts)}"
      )
      terminal.println()
      return
    }

    val totalAttemptTimings = attemptTimings.map { it.total }

    terminal.println(
        "  Attempts     $attempted attempted in ${durationText(timings.attempts)} | " +
            "avg connect ${durationText(checkNotNull(average(totalAttemptTimings)))} | " +
            "$skipped skipped"
    )
    terminal.println()
  }

  private fun resultLine(result: ProbeAttemptResult): String {
    val entry = result.entry
    val status =
        if (result.readSucceeded) {
          successText(fixed("OK", STATUS_WIDTH))
        } else {
          failureText(fixed("FAIL", STATUS_WIDTH))
        }

    return "    " +
        status +
        " " +
        fixed(entry.securityPolicy ?: "unknown-policy", POLICY_WIDTH) +
        " " +
        fixed(entry.messageSecurityMode, MODE_WIDTH) +
        " " +
        fixed(entry.userTokenPolicy, TOKEN_WIDTH) +
        " " +
        fixedRight(result.timing?.total?.let(::durationText) ?: "-", CONNECT_WIDTH)
  }

  private fun resultGroups(
      results: List<ProbeAttemptResult>
  ): Map<ResultCategory, List<ProbeAttemptResult>> =
      results.groupBy { ResultCategory.from(it.entry) }

  private fun failureGroups(results: List<ProbeAttemptResult>): Map<FailureKey, Int> =
      results
          .mapNotNull { result ->
            val category = result.failureCategory ?: return@mapNotNull null
            FailureKey(
                category = category,
                combo = combo(result.entry),
                message = result.failureMessage ?: "no message",
            )
          }
          .groupingBy { it }
          .eachCount()

  private fun sortedFailures(failures: Map<FailureKey, Int>): List<Map.Entry<FailureKey, Int>> =
      failures.entries.sortedWith(
          compareByDescending<Map.Entry<FailureKey, Int>> { it.value }
              .thenBy { it.key.category.name }
              .thenBy { it.key.combo }
              .thenBy { it.key.message }
      )

  private fun notAdvertisedGroups(entries: List<ProbeEntry>): Map<String, List<ProbeEntry>> =
      sortedEntries(entries.filter { it.status == ProbeEntryStatus.NOT_ADVERTISED }).groupBy {
        it.securityPolicy ?: "unknown-policy"
      }

  private fun missingCombinations(entries: List<ProbeEntry>): String =
      sortedEntries(entries)
          .groupBy({ it.messageSecurityMode }, { it.userTokenPolicy })
          .entries
          .joinToString("; ") { (mode, tokens) -> "$mode: ${tokens.distinct().joinToString()}" }

  private fun sortedResults(results: List<ProbeAttemptResult>): List<ProbeAttemptResult> =
      results.sortedWith(
          probeOrder(
              policy = { it.entry.securityPolicy },
              mode = { it.entry.messageSecurityMode },
              token = { it.entry.userTokenPolicy },
          )
      )

  private fun sortedEntries(entries: List<ProbeEntry>): List<ProbeEntry> =
      entries.sortedWith(
          probeOrder(
              policy = { it.securityPolicy },
              mode = { it.messageSecurityMode },
              token = { it.userTokenPolicy },
          )
      )
}

private fun <T> probeOrder(
    policy: (T) -> String?,
    mode: (T) -> String,
    token: (T) -> String,
): Comparator<T> =
    compareBy<T> { policyRank(policy(it)) }
        .thenBy { policy(it) ?: "" }
        .thenBy { modeRank(mode(it)) }
        .thenBy(mode)
        .thenBy { tokenRank(token(it)) }
        .thenBy(token)

private abstract class CountingProbeProgress(
    protected val running: AtomicBoolean,
    protected val completed: AtomicInteger,
    protected val failures: AtomicInteger,
) : ProbeProgress {
  override fun attemptCompleted(result: ProbeAttemptResult) {
    completed.incrementAndGet()
    if (result.failureCategory != null) {
      failures.incrementAndGet()
    }
  }
}

private abstract class ScheduledProbeProgress(
    protected val total: Int,
    running: AtomicBoolean,
    completed: AtomicInteger,
    failures: AtomicInteger,
) : CountingProbeProgress(running, completed, failures) {
  private val tick = AtomicInteger()
  private val executor: ScheduledExecutorService =
      Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "ecc-demo-client-probe-progress").also { it.isDaemon = true }
      }
  private lateinit var future: ScheduledFuture<*>

  protected fun startSchedule(interval: Long, unit: TimeUnit) {
    render()
    future = executor.scheduleAtFixedRate({ if (running.get()) render() }, interval, interval, unit)
  }

  override fun close() {
    running.set(false)
    if (::future.isInitialized) future.cancel(false)
    executor.shutdownNow()
    cleanup()
  }

  protected open fun cleanup() {}

  protected fun currentLine(): String {
    val frame = SPINNER_FRAMES[tick.getAndIncrement() % SPINNER_FRAMES.size]
    return progressLine(frame, completed.get(), total, failureSuffix(failures.get()))
  }

  protected abstract fun render()
}

private class LoggingProbeProgress(
    private val terminal: Terminal,
    total: Int,
    running: AtomicBoolean,
    completed: AtomicInteger,
    failures: AtomicInteger,
) : ScheduledProbeProgress(total, running, completed, failures) {
  init {
    startSchedule(LOG_PROGRESS_INTERVAL_SECONDS, TimeUnit.SECONDS)
  }

  override fun render() {
    terminal.println(currentLine())
  }
}

private class InlineProbeProgress(
    private val terminal: Terminal,
    total: Int,
    running: AtomicBoolean,
    completed: AtomicInteger,
    failures: AtomicInteger,
) : ScheduledProbeProgress(total, running, completed, failures) {
  private val renderLock = Any()
  private var lastWidth = 0

  init {
    startSchedule(INLINE_PROGRESS_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)
  }

  override fun render() {
    val line = currentLine()
    synchronized(renderLock) {
      val padding = " ".repeat((lastWidth - line.length).coerceAtLeast(0))
      rawPrint("\r$line$padding")
      lastWidth = line.length
    }
  }

  override fun cleanup() {
    synchronized(renderLock) {
      rawPrint("\r" + " ".repeat(lastWidth) + "\r")
      lastWidth = 0
    }
  }

  private fun rawPrint(text: String) {
    terminal.rawPrint(text)
    System.out.flush()
  }
}

private class AnimatedProbeProgress(
    running: AtomicBoolean,
    completed: AtomicInteger,
    failures: AtomicInteger,
    private val animator: BlockingAnimator,
    private val future: Future<*>,
) : CountingProbeProgress(running, completed, failures) {
  override fun close() {
    running.set(false)
    animator.clear()
    future.cancel(false)
  }
}

private data class ReportStats(
    val advertised: Int,
    val filtered: Int,
    val localSupport: LocalSupportBreakdown,
    val notAdvertised: Int,
    val attempted: Int,
    val readSuccess: Int,
    val failures: Int,
    val skipped: Int,
) {
  companion object {
    fun from(summary: ProbeSummary): ReportStats {
      val attempted = summary.results.count { it.attempted }
      val readSuccess = summary.results.count { it.readSucceeded }
      val failures = summary.results.count { it.failureCategory != null }

      return ReportStats(
          advertised = summary.entries.count { it.advertised },
          filtered = summary.entries.count { it.status == ProbeEntryStatus.FILTERED },
          localSupport = LocalSupportBreakdown.from(summary.entries),
          notAdvertised = summary.entries.count { it.status == ProbeEntryStatus.NOT_ADVERTISED },
          attempted = attempted,
          readSuccess = readSuccess,
          failures = failures,
          skipped = summary.results.size - attempted,
      )
    }
  }
}

private data class LocalSupportBreakdown(
    val missingCredentials: Int,
    val unsupportedUserToken: Int,
    val policyRuntime: Int,
) {
  companion object {
    fun from(entries: List<ProbeEntry>): LocalSupportBreakdown {
      var missingCredentials = 0
      var unsupportedUserToken = 0
      var policyRuntime = 0

      for (entry in entries.filter { it.status == ProbeEntryStatus.UNSUPPORTED_LOCAL }) {
        when (classify(entry.reason)) {
          LocalSupportGap.MISSING_CREDENTIALS -> missingCredentials++
          LocalSupportGap.UNSUPPORTED_USER_TOKEN -> unsupportedUserToken++
          LocalSupportGap.POLICY_RUNTIME -> policyRuntime++
        }
      }

      return LocalSupportBreakdown(missingCredentials, unsupportedUserToken, policyRuntime)
    }

    private fun classify(reason: String?): LocalSupportGap {
      val normalized = reason.orEmpty().lowercase()

      if ("--username" in normalized || "--password" in normalized || "credentials" in normalized) {
        return LocalSupportGap.MISSING_CREDENTIALS
      }
      if (
          "user-token policy is not supported" in normalized ||
              "unsupported user-token" in normalized
      ) {
        return LocalSupportGap.UNSUPPORTED_USER_TOKEN
      }

      return LocalSupportGap.POLICY_RUNTIME
    }
  }
}

private enum class LocalSupportGap {
  MISSING_CREDENTIALS,
  UNSUPPORTED_USER_TOKEN,
  POLICY_RUNTIME,
}

private enum class ResultCategory(val displayName: String) {
  NO_SECURITY("No Security"),
  RSA("RSA"),
  RSA_SHA256_CERTIFICATE("RsaSha256"),
  ECC_NIST_P256_CERTIFICATE("EccNistP256"),
  ECC_NIST_P384_CERTIFICATE("EccNistP384"),
  ECC_BRAINPOOL_P256R1_CERTIFICATE("EccBrainpoolP256r1"),
  ECC_BRAINPOOL_P384R1_CERTIFICATE("EccBrainpoolP384r1"),
  ECC_CURVE25519_CERTIFICATE("EccCurve25519"),
  ECC_CURVE448_CERTIFICATE("EccCurve448"),
  OTHER("Other");

  companion object {
    private val OLD_RSA_POLICIES =
        setOf(
            "Basic256Sha256",
            "Aes128_Sha256_RsaOaep",
            "Aes256_Sha256_RsaPss",
        )

    private val CERTIFICATE_TYPE_CATEGORIES =
        mapOf(
            NodeIds.RsaSha256ApplicationCertificateType to RSA_SHA256_CERTIFICATE,
            NodeIds.EccNistP256ApplicationCertificateType to ECC_NIST_P256_CERTIFICATE,
            NodeIds.EccNistP384ApplicationCertificateType to ECC_NIST_P384_CERTIFICATE,
            NodeIds.EccBrainpoolP256r1ApplicationCertificateType to
                ECC_BRAINPOOL_P256R1_CERTIFICATE,
            NodeIds.EccBrainpoolP384r1ApplicationCertificateType to
                ECC_BRAINPOOL_P384R1_CERTIFICATE,
            NodeIds.EccCurve25519ApplicationCertificateType to ECC_CURVE25519_CERTIFICATE,
            NodeIds.EccCurve448ApplicationCertificateType to ECC_CURVE448_CERTIFICATE,
        )

    fun from(entry: ProbeEntry): ResultCategory {
      val policy = entry.securityPolicy.orEmpty()

      if (policy == "None") return NO_SECURITY
      if (policy in OLD_RSA_POLICIES) return RSA

      val certificateType =
          runCatching {
                SecurityPolicy.valueOf(policy).profile.preferredCertificateTypeId().orElse(null)
              }
              .getOrNull()

      return CERTIFICATE_TYPE_CATEGORIES[certificateType] ?: OTHER
    }
  }
}

private data class FailureKey(
    val category: ProbeFailureCategory,
    val combo: String,
    val message: String,
)

private fun policyRank(policy: String?): Int {
  val rank = DEFAULT_SECURITY_POLICIES.indexOf(policy.orEmpty())
  return if (rank >= 0) rank else Int.MAX_VALUE
}

private fun modeRank(mode: String): Int =
    when (mode) {
      "None" -> 0
      "Sign" -> 1
      "SignAndEncrypt" -> 2
      else -> Int.MAX_VALUE
    }

private fun tokenRank(token: String): Int =
    when (token) {
      "Anonymous" -> 0
      "UserName" -> 1
      else -> Int.MAX_VALUE
    }

private fun targetLabel(targetUrl: String): String =
    try {
      val uri = URI.create(targetUrl)
      val host = uri.host
      val port = if (uri.port >= 0) ":${uri.port}" else ""
      if (host.isNullOrBlank()) targetUrl else "$host$port"
    } catch (_: IllegalArgumentException) {
      targetUrl
    }

private fun localGaps(localSupport: LocalSupportBreakdown): String =
    "${localSupport.missingCredentials} missing credentials | " +
        "${localSupport.unsupportedUserToken} unsupported token | " +
        "${localSupport.policyRuntime} policy/runtime"

private fun combo(entry: ProbeEntry): String =
    "${entry.securityPolicy ?: "unknown-policy"} / ${entry.messageSecurityMode} / " +
        entry.userTokenPolicy

private fun ProbeFailureCategory.displayName(): String = name.lowercase().replace('_', ' ')

private fun meter(label: String, value: Int, total: Int, valueText: String): String {
  val filled =
      if (total == 0) 0
      else (value.toDouble() * BAR_WIDTH / total).roundToInt().coerceIn(0, BAR_WIDTH)
  val empty = BAR_WIDTH - filled

  return rowLabel(label) + "[" + "#".repeat(filled) + "-".repeat(empty) + "] " + valueText
}

private fun row(label: String, value: String): String = rowLabel(label) + value

private fun rowLabel(label: String): String = label.padEnd(13) + " "

private fun fixed(value: String, width: Int): String =
    if (value.length > width) value else value.padEnd(width)

private fun fixedRight(value: String, width: Int): String =
    if (value.length > width) value else value.padStart(width)

private fun rule(): String = "-".repeat(RULE_WIDTH)

private fun section(text: String): String = title(text)

private fun title(text: String): String = brightBlue(text)

private fun warningText(text: String): String = brightYellow(text)

private fun successText(text: String): String = green(text)

private fun failureText(text: String): String = red(text)

private fun durationText(duration: Duration): String {
  val nanos = duration.toNanos()
  return when {
    nanos < 1_000_000L -> "%.1f us".format(nanos / 1_000.0)
    nanos < 1_000_000_000L -> "%.1f ms".format(nanos / 1_000_000.0)
    nanos < 60_000_000_000L -> "%.2f s".format(nanos / 1_000_000_000.0)
    else -> {
      val minutes = duration.toMinutes()
      val seconds = (nanos - Duration.ofMinutes(minutes).toNanos()) / 1_000_000_000.0
      "%dm %.1fs".format(minutes, seconds)
    }
  }
}

private fun average(durations: List<Duration>): Duration? {
  if (durations.isEmpty()) return null

  return Duration.ofNanos(durations.sumOf { it.toNanos() } / durations.size)
}

private fun progressLine(
    frame: String,
    completed: Int,
    total: Int,
    failureSuffix: String,
): String = "$frame Running probes: $completed/$total attempts complete$failureSuffix"

private fun failureSuffix(failures: Int): String =
    if (failures > 0) {
      ", $failures failed"
    } else {
      ""
    }

private fun shouldUseLogProgress(): Boolean =
    System.getenv("CI") != null || System.getenv("TERM").equals("dumb", ignoreCase = true)
