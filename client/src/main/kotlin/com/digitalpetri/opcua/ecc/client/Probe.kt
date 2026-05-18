package com.digitalpetri.opcua.ecc.client

import java.nio.file.Path
import java.time.Duration
import java.util.HexFormat
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import org.eclipse.milo.opcua.sdk.client.DiscoveryClient
import org.eclipse.milo.opcua.sdk.client.OpcUaClient
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfig
import org.eclipse.milo.opcua.sdk.client.identity.AnonymousProvider
import org.eclipse.milo.opcua.sdk.client.identity.IdentityProvider
import org.eclipse.milo.opcua.sdk.client.identity.UsernameProvider
import org.eclipse.milo.opcua.stack.core.NodeIds
import org.eclipse.milo.opcua.stack.core.Stack
import org.eclipse.milo.opcua.stack.core.StatusCodes
import org.eclipse.milo.opcua.stack.core.UaException
import org.eclipse.milo.opcua.stack.core.UaExceptionStatus
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode
import org.eclipse.milo.opcua.stack.core.types.enumerated.ServerState
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy
import org.eclipse.milo.opcua.stack.core.util.CertificateUtil
import org.eclipse.milo.opcua.stack.transport.client.tcp.OpcTcpClientTransportConfigBuilder

private val DISCOVERY_TIMEOUT: Duration = Duration.ofSeconds(10)
private val CONNECT_TIMEOUT: Duration = Duration.ofSeconds(15)
private val READ_TIMEOUT: Duration = Duration.ofSeconds(10)
private val DISCONNECT_TIMEOUT: Duration = Duration.ofSeconds(5)
private const val REQUEST_TIMEOUT_MILLIS = 5_000
private const val SESSION_TIMEOUT_MILLIS = 10_000
private val HEX: HexFormat = HexFormat.of()
private val STANDARD_NODE_IDS =
    listOf(
        NodeIds.Server_ServerStatus_State,
        NodeIds.Server_ServerStatus_CurrentTime,
    )

/**
 * Planning status for one policy/mode/token combination.
 *
 * A combination can be present and ready to attempt, excluded by local filters, unsupported by this
 * client run, or absent from the target server's discovery response.
 */
internal enum class ProbeEntryStatus {
  ADVERTISED,
  FILTERED,
  UNSUPPORTED_LOCAL,
  NOT_ADVERTISED,
}

/** Final outcome for a planned probe entry. */
internal enum class ProbeOutcome {
  SKIPPED,
  SUCCESS,
  CONNECTION_FAILURE,
  READ_FAILURE,
}

/** Per-stage result used to show where an attempted probe stopped. */
internal enum class ProbeStepResult {
  NOT_ATTEMPTED,
  SUCCESS,
  FAILURE,
}

/**
 * Broad failure category for an attempted OPC UA session.
 *
 * The categories follow the session setup order: secure channel negotiation, session activation
 * with a user identity token, then reads over the activated session.
 */
internal enum class ProbeFailureCategory {
  SECURE_CHANNEL_FAILURE,
  SESSION_ACTIVATION_FAILURE,
  READ_FAILURE,
}

/**
 * Normalized endpoint discovered from a target server.
 *
 * Milo exposes endpoint descriptions as protocol structures. The probe keeps the raw value for
 * client configuration and stores parsed fields beside it so planning and terminal output can
 * reason about policies, message modes, certificates, and user tokens without repeatedly decoding
 * the raw structure.
 */
internal data class AdvertisedEndpoint(
    val raw: EndpointDescription,
    val endpointUrl: String?,
    val securityPolicyUri: String?,
    val securityPolicy: SecurityPolicy?,
    val messageSecurityMode: MessageSecurityMode,
    val transportProfileUri: String?,
    val serverCertificateThumbprint: String?,
    val userTokenPolicies: List<AdvertisedUserToken>,
)

/**
 * User identity token advertised on an endpoint.
 *
 * OPC UA endpoints can offer multiple identity mechanisms for the same security policy and message
 * mode. The demo client supports anonymous and username tokens, while still reporting unsupported
 * token types it discovers.
 */
internal data class AdvertisedUserToken(
    val policyId: String?,
    val tokenType: UserTokenType,
    val securityPolicyUri: String?,
) {
  /** Name used by client filters, or null when this client cannot attempt the token type. */
  val clientTokenName: String?
    get() =
        when (tokenType) {
          UserTokenType.Anonymous -> "Anonymous"
          UserTokenType.UserName -> "UserName"
          else -> null
        }

  /** Name shown in reports, preserving unknown token types for troubleshooting. */
  val reportName: String
    get() = clientTokenName ?: tokenType.name
}

/**
 * One row in the client probe plan.
 *
 * A row represents a single security policy, message security mode, and user token combination.
 * Rows are kept even when they are skipped so the final report can separate target coverage,
 * operator filters, missing credentials, and unsupported local capabilities.
 */
internal data class ProbeEntry(
    val endpoint: EndpointDescription?,
    val endpointUrl: String?,
    val securityPolicyUri: String?,
    val securityPolicy: String?,
    val messageSecurityMode: String,
    val userTokenPolicy: String,
    val userTokenPolicyId: String?,
    val userTokenSecurityPolicyUri: String?,
    val advertised: Boolean,
    val selected: Boolean,
    val locallyAttemptable: Boolean,
    val status: ProbeEntryStatus,
    val reason: String?,
    val serverCertificateThumbprint: String?,
) {
  /** True when this row has all information needed to attempt a real OPC UA session. */
  val shouldAttempt: Boolean
    get() =
        status == ProbeEntryStatus.ADVERTISED && selected && locallyAttemptable && endpoint != null
}

/**
 * Values read from standard server nodes after a session is activated.
 *
 * These reads are intentionally simple: they prove the negotiated session can use the standard OPC
 * UA address space without depending on the demo namespace.
 */
internal data class StandardReadValues(
    val serverState: String,
    val currentTime: String,
)

/** Runtime measurements for one attempted OPC UA connection/session setup. */
internal data class ProbeAttemptTiming(
    val total: Duration,
)

/**
 * Result for one planned probe row.
 *
 * The step fields let terminal output distinguish secure-channel failures from session activation
 * failures and read failures. That distinction matters when comparing ECC/RSA-DH policy support
 * against username-token behavior.
 */
internal data class ProbeAttemptResult(
    val entry: ProbeEntry,
    val outcome: ProbeOutcome,
    val secureChannelResult: ProbeStepResult,
    val sessionResult: ProbeStepResult,
    val readResult: ProbeStepResult,
    val readValues: StandardReadValues?,
    val failureCategory: ProbeFailureCategory?,
    val failureMessage: String?,
    val timing: ProbeAttemptTiming?,
) {
  /** True when the probe opened a client and made at least one connection-stage attempt. */
  val attempted: Boolean
    get() =
        secureChannelResult != ProbeStepResult.NOT_ATTEMPTED ||
            sessionResult != ProbeStepResult.NOT_ATTEMPTED ||
            readResult != ProbeStepResult.NOT_ATTEMPTED

  /** True when the secure channel, session activation, and standard reads all succeeded. */
  val readSucceeded: Boolean
    get() = readResult == ProbeStepResult.SUCCESS

  companion object {
    fun skipped(entry: ProbeEntry): ProbeAttemptResult =
        ProbeAttemptResult(
            entry = entry,
            outcome = ProbeOutcome.SKIPPED,
            secureChannelResult = ProbeStepResult.NOT_ATTEMPTED,
            sessionResult = ProbeStepResult.NOT_ATTEMPTED,
            readResult = ProbeStepResult.NOT_ATTEMPTED,
            readValues = null,
            failureCategory = null,
            failureMessage = entry.reason,
            timing = null,
        )

    fun success(
        entry: ProbeEntry,
        readValues: StandardReadValues,
        timing: ProbeAttemptTiming,
    ): ProbeAttemptResult =
        ProbeAttemptResult(
            entry = entry,
            outcome = ProbeOutcome.SUCCESS,
            secureChannelResult = ProbeStepResult.SUCCESS,
            sessionResult = ProbeStepResult.SUCCESS,
            readResult = ProbeStepResult.SUCCESS,
            readValues = readValues,
            failureCategory = null,
            failureMessage = null,
            timing = timing,
        )

    fun connectionFailure(
        entry: ProbeEntry,
        failure: Throwable,
        timing: ProbeAttemptTiming?,
    ): ProbeAttemptResult {
      val category = classifyConnectionFailure(failure)

      return ProbeAttemptResult(
          entry = entry,
          outcome = ProbeOutcome.CONNECTION_FAILURE,
          secureChannelResult =
              if (category == ProbeFailureCategory.SESSION_ACTIVATION_FAILURE) {
                ProbeStepResult.SUCCESS
              } else {
                ProbeStepResult.FAILURE
              },
          sessionResult =
              if (category == ProbeFailureCategory.SESSION_ACTIVATION_FAILURE) {
                ProbeStepResult.FAILURE
              } else {
                ProbeStepResult.NOT_ATTEMPTED
              },
          readResult = ProbeStepResult.NOT_ATTEMPTED,
          readValues = null,
          failureCategory = category,
          failureMessage = describeFailure(failure),
          timing = timing,
      )
    }

    fun readFailure(
        entry: ProbeEntry,
        failure: Throwable,
        timing: ProbeAttemptTiming,
    ): ProbeAttemptResult =
        ProbeAttemptResult(
            entry = entry,
            outcome = ProbeOutcome.READ_FAILURE,
            secureChannelResult = ProbeStepResult.SUCCESS,
            sessionResult = ProbeStepResult.SUCCESS,
            readResult = ProbeStepResult.FAILURE,
            readValues = null,
            failureCategory = ProbeFailureCategory.READ_FAILURE,
            failureMessage = describeFailure(failure),
            timing = timing,
        )
  }
}

/**
 * Runtime measurements for the full probe.
 *
 * Attempts covers the serial execution of all planned rows.
 */
internal data class ProbeRunTimings(
    val total: Duration,
    val attempts: Duration,
)

/**
 * Probe plan emitted after discovery but before connection attempts start.
 *
 * Renderers use this preview to show how much work will run and which local identity is active
 * while the slower network attempts are still pending.
 */
internal data class ProbePlanPreview(
    val options: ClientOptions,
    val keyStorePath: Path,
    val advertisedEndpointCount: Int,
    val entries: List<ProbeEntry>,
    val remoteCertificatesAutoTrusted: Boolean = true,
)

/**
 * Receives progress callbacks while probe attempts run.
 *
 * Implementations may render animated, inline, or log-style progress, but they should treat
 * callbacks as best-effort reporting and avoid influencing probe behavior.
 */
internal interface ProbeProgress : AutoCloseable {
  fun attemptCompleted(result: ProbeAttemptResult)

  override fun close()
}

/** Progress sink used when no terminal progress renderer is needed. */
internal object NoProbeProgress : ProbeProgress {
  override fun attemptCompleted(result: ProbeAttemptResult) {}

  override fun close() {}
}

/**
 * Complete result of a client probe run.
 *
 * The summary includes both the plan and attempt results so terminal output can explain skipped
 * combinations as well as successful or failed sessions.
 */
internal data class ProbeSummary(
    val options: ClientOptions,
    val keyStorePath: Path,
    val advertisedEndpointCount: Int,
    val entries: List<ProbeEntry>,
    val results: List<ProbeAttemptResult>,
    val timings: ProbeRunTimings,
    val remoteCertificatesAutoTrusted: Boolean = true,
    val miloSdkVersion: String = OpcUaClient.SDK_VERSION,
    val miloStackVersion: String = Stack.VERSION,
)

/**
 * Discovers, plans, and attempts endpoint/user-token combinations for one target server.
 *
 * The probe first asks the server what it advertises, builds a row for every relevant combination,
 * then attempts only rows that are selected, locally supported, and still advertised. Successful
 * attempts include standard server reads so a connection success also proves basic session use.
 */
internal fun runProbe(
    options: ClientOptions,
    onPlanReady: (ProbePlanPreview) -> Unit = {},
    onProbeAttemptsStarted: (ProbePlanPreview) -> ProbeProgress = { NoProbeProgress },
): ProbeSummary {
  val totalStartedAt = System.nanoTime()
  initializeClientSecurity(options).use { security ->
    val discovered = discover(options.targetUrl)
    val advertised = discovered.map(::normalizeEndpoint)
    val entries = buildProbePlan(options, advertised)

    val preview =
        ProbePlanPreview(
            options = options,
            keyStorePath = security.keyStorePath,
            advertisedEndpointCount = advertised.size,
            entries = entries,
        )
    onPlanReady(preview)

    val attemptsStartedAt = System.nanoTime()
    val results =
        onProbeAttemptsStarted(preview).use { progress ->
          entries.map { entry ->
            val result =
                if (!entry.shouldAttempt) {
                  ProbeAttemptResult.skipped(entry)
                } else {
                  attempt(options, security, entry, discovered)
                }
            if (result.attempted) {
              progress.attemptCompleted(result)
            }
            result
          }
        }
    val attemptsDuration = elapsedSince(attemptsStartedAt)

    return ProbeSummary(
        options = options,
        keyStorePath = security.keyStorePath,
        advertisedEndpointCount = advertised.size,
        entries = entries,
        results = results,
        timings =
            ProbeRunTimings(
                total = elapsedSince(totalStartedAt),
                attempts = attemptsDuration,
            ),
    )
  }
}

private fun discover(targetUrl: String): List<EndpointDescription> =
    DiscoveryClient.getEndpoints(targetUrl, ::configureTransport)
        .get(DISCOVERY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)

private fun normalizeEndpoint(endpoint: EndpointDescription): AdvertisedEndpoint {
  val securityPolicyUri = endpoint.securityPolicyUri
  val securityPolicy = securityPolicyUri?.let { SecurityPolicy.fromUriSafe(it).orElse(null) }

  return AdvertisedEndpoint(
      raw = endpoint,
      endpointUrl = endpoint.endpointUrl,
      securityPolicyUri = securityPolicyUri,
      securityPolicy = securityPolicy,
      messageSecurityMode = endpoint.securityMode ?: MessageSecurityMode.Invalid,
      transportProfileUri = endpoint.transportProfileUri,
      serverCertificateThumbprint = thumbprint(endpoint.serverCertificate),
      userTokenPolicies =
          endpoint.userIdentityTokens?.filterNotNull()?.map {
            AdvertisedUserToken(it.policyId, it.tokenType, it.securityPolicyUri)
          } ?: emptyList(),
  )
}

private fun buildProbePlan(
    options: ClientOptions,
    advertisedEndpoints: List<AdvertisedEndpoint>,
): List<ProbeEntry> {
  val entries = mutableListOf<ProbeEntry>()
  val advertisedKeys = mutableSetOf<CombinationKey>()

  // Treat endpoint plus user token as the unit of work. OPC UA negotiates the secure channel from
  // the endpoint, then activates the session with exactly one identity token.
  for (endpoint in advertisedEndpoints) {
    for (userTokenPolicy in endpoint.userTokenPolicies) {
      val tokenName = userTokenPolicy.clientTokenName
      if (endpoint.securityPolicy != null && tokenName != null) {
        advertisedKeys +=
            CombinationKey(endpoint.securityPolicy, endpoint.messageSecurityMode, tokenName)
      }

      entries += advertisedEntry(options, endpoint, userTokenPolicy)
    }
  }

  // Add selected combinations that discovery did not return so the report can call out server-side
  // coverage gaps separately from local filters or connection failures.
  val selectedPolicies = options.policies.map(SecurityPolicy::valueOf)
  val selectedModes = options.modes.map(MessageSecurityMode::valueOf)
  for (policy in selectedPolicies) {
    for (mode in selectedModes) {
      if (!isPolicyModeCandidate(policy, mode)) continue
      for (token in options.tokens) {
        val key = CombinationKey(policy, mode, token)
        if (key in advertisedKeys) continue

        entries +=
            ProbeEntry(
                endpoint = null,
                endpointUrl = null,
                securityPolicyUri = policy.uri,
                securityPolicy = policy.name,
                messageSecurityMode = mode.name,
                userTokenPolicy = token,
                userTokenPolicyId = null,
                userTokenSecurityPolicyUri = null,
                advertised = false,
                selected = true,
                locallyAttemptable = false,
                status = ProbeEntryStatus.NOT_ADVERTISED,
                reason = "Target did not advertise this selected combination.",
                serverCertificateThumbprint = null,
            )
      }
    }
  }

  return entries
}

private fun advertisedEntry(
    options: ClientOptions,
    endpoint: AdvertisedEndpoint,
    userTokenPolicy: AdvertisedUserToken,
): ProbeEntry {
  val policy = endpoint.securityPolicy
  val tokenName = userTokenPolicy.clientTokenName ?: userTokenPolicy.reportName

  if (policy == null) {
    return unsupported(
        endpoint,
        userTokenPolicy,
        tokenName,
        "Unknown or unsupported security policy URI.",
    )
  }
  if (endpoint.messageSecurityMode == MessageSecurityMode.Invalid) {
    return unsupported(endpoint, userTokenPolicy, tokenName, "Invalid message security mode.")
  }
  if (userTokenPolicy.clientTokenName == null) {
    return unsupported(
        endpoint,
        userTokenPolicy,
        tokenName,
        "User-token policy is not supported by this client.",
    )
  }
  if (!isPolicyModeCandidate(policy, endpoint.messageSecurityMode)) {
    return filtered(endpoint, userTokenPolicy, tokenName, "Outside the built-in event profile.")
  }
  if (
      policy.name !in options.policies ||
          endpoint.messageSecurityMode.name !in options.modes ||
          tokenName !in options.tokens
  ) {
    return filtered(endpoint, userTokenPolicy, tokenName, "Excluded by CLI filters.")
  }
  if (tokenName == "UserName" && (options.username == null || options.password == null)) {
    return unsupported(
        endpoint,
        userTokenPolicy,
        tokenName,
        "Username token attempts require --username and --password.",
    )
  }
  if (endpoint.endpointUrl == null) {
    return unsupported(endpoint, userTokenPolicy, tokenName, "Endpoint URL is missing.")
  }

  return ProbeEntry(
      endpoint = endpoint.raw,
      endpointUrl = endpoint.endpointUrl,
      securityPolicyUri = policy.uri,
      securityPolicy = policy.name,
      messageSecurityMode = endpoint.messageSecurityMode.name,
      userTokenPolicy = tokenName,
      userTokenPolicyId = userTokenPolicy.policyId,
      userTokenSecurityPolicyUri = userTokenPolicy.securityPolicyUri,
      advertised = true,
      selected = true,
      locallyAttemptable = true,
      status = ProbeEntryStatus.ADVERTISED,
      reason = null,
      serverCertificateThumbprint = endpoint.serverCertificateThumbprint,
  )
}

private fun filtered(
    endpoint: AdvertisedEndpoint,
    userTokenPolicy: AdvertisedUserToken,
    tokenName: String,
    reason: String,
): ProbeEntry =
    nonAttemptableEntry(
        endpoint,
        userTokenPolicy,
        tokenName,
        status = ProbeEntryStatus.FILTERED,
        selected = false,
        reason = reason,
    )

private fun unsupported(
    endpoint: AdvertisedEndpoint,
    userTokenPolicy: AdvertisedUserToken,
    tokenName: String,
    reason: String,
): ProbeEntry =
    nonAttemptableEntry(
        endpoint,
        userTokenPolicy,
        tokenName,
        status = ProbeEntryStatus.UNSUPPORTED_LOCAL,
        selected = true,
        reason = reason,
    )

private fun nonAttemptableEntry(
    endpoint: AdvertisedEndpoint,
    userTokenPolicy: AdvertisedUserToken,
    tokenName: String,
    status: ProbeEntryStatus,
    selected: Boolean,
    reason: String,
): ProbeEntry =
    ProbeEntry(
        endpoint = endpoint.raw,
        endpointUrl = endpoint.endpointUrl,
        securityPolicyUri = endpoint.securityPolicyUri,
        securityPolicy = endpoint.securityPolicy?.name,
        messageSecurityMode = endpoint.messageSecurityMode.name,
        userTokenPolicy = tokenName,
        userTokenPolicyId = userTokenPolicy.policyId,
        userTokenSecurityPolicyUri = userTokenPolicy.securityPolicyUri,
        advertised = true,
        selected = selected,
        locallyAttemptable = false,
        status = status,
        reason = reason,
        serverCertificateThumbprint = endpoint.serverCertificateThumbprint,
    )

private fun attempt(
    options: ClientOptions,
    security: ClientSecurityContext,
    entry: ProbeEntry,
    discoveryEndpoints: List<EndpointDescription>,
): ProbeAttemptResult {
  var client: OpcUaClient? = null
  var sessionActive = false
  var readValues: StandardReadValues? = null
  var failure: Exception? = null
  var connectionStartedAt: Long? = null
  var connectionDuration: Duration? = null

  try {
    val endpoint = entry.endpoint ?: error("shouldAttempt guarantees endpoint is non-null")
    val identityProvider = identityProvider(options, entry, security)
    val config = clientConfig(security, endpoint, discoveryEndpoints, identityProvider)
    client = OpcUaClient.create(config, ::configureTransport)

    // connectAsync covers secure-channel creation and session activation. The duration stops here
    // so standard reads and disconnect cleanup do not affect per-policy setup measurements.
    connectionStartedAt = System.nanoTime()
    awaitConnection(client.connectAsync())
    connectionDuration = elapsedSince(connectionStartedAt)
    sessionActive = true

    readValues = readStandardValues(client)
  } catch (e: Exception) {
    if (connectionDuration == null) {
      connectionDuration = connectionStartedAt?.let(::elapsedSince)
    }
    failure = e
  } finally {
    disconnectQuietly(client)
  }

  val timing = connectionDuration?.let { ProbeAttemptTiming(total = it) }

  return when {
    failure == null ->
        ProbeAttemptResult.success(entry, checkNotNull(readValues), checkNotNull(timing))
    sessionActive -> ProbeAttemptResult.readFailure(entry, failure, checkNotNull(timing))
    else -> ProbeAttemptResult.connectionFailure(entry, failure, timing)
  }
}

private fun matchesToken(entry: ProbeEntry, policy: UserTokenPolicy): Boolean {
  val tokenMatches =
      when (entry.userTokenPolicy) {
        "Anonymous" -> policy.tokenType == UserTokenType.Anonymous
        "UserName" -> policy.tokenType == UserTokenType.UserName
        else -> false
      }

  return tokenMatches &&
      (entry.userTokenPolicyId == null || entry.userTokenPolicyId == policy.policyId) &&
      (entry.userTokenSecurityPolicyUri == null ||
          entry.userTokenSecurityPolicyUri == policy.securityPolicyUri)
}

private fun identityProvider(
    options: ClientOptions,
    entry: ProbeEntry,
    security: ClientSecurityContext,
): IdentityProvider =
    when (entry.userTokenPolicy) {
      "Anonymous" -> AnonymousProvider.INSTANCE
      "UserName" ->
          UsernameProvider(
              options.username,
              options.password,
              security.certificateValidator,
          ) { policies ->
            policies.firstOrNull { policy -> matchesToken(entry, policy) }
                ?: throw IllegalArgumentException(
                    "Target endpoint no longer advertises planned username token policy."
                )
          }
      else -> error("unsupported user-token policy: ${entry.userTokenPolicy}")
    }

private fun clientConfig(
    security: ClientSecurityContext,
    endpoint: EndpointDescription,
    discoveryEndpoints: List<EndpointDescription>,
    identityProvider: IdentityProvider,
): OpcUaClientConfig =
    OpcUaClientConfig.builder()
        .setEndpoint(endpoint)
        .setDiscoveryEndpoints(discoveryEndpoints)
        .setApplicationName(LocalizedText.english("ECC Demo Probe Client"))
        .setApplicationUri(CLIENT_APPLICATION_URI)
        .setProductUri("urn:eclipse:milo:ecc-demo")
        .setRequestTimeout(uint(REQUEST_TIMEOUT_MILLIS))
        .setSessionTimeout(uint(SESSION_TIMEOUT_MILLIS))
        .setCertificateManager(security.certificateManager)
        .setCertificateValidator(security.certificateValidator)
        .setIdentityProvider(identityProvider)
        // Interop targets often advertise hostnames that differ from the caller's URL, especially
        // in Docker and localhost smoke runs. Keep validation relaxed and surface trust posture
        // instead.
        .setSessionEndpointValidationEnabled(false)
        .build()

private fun readStandardValues(client: OpcUaClient): StandardReadValues {
  val values =
      client
          .readValuesAsync(0.0, TimestampsToReturn.Both, STANDARD_NODE_IDS)
          .get(READ_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)

  if (values.size != STANDARD_NODE_IDS.size) {
    throw UaException(
        StatusCodes.Bad_UnexpectedError,
        "standard read returned ${values.size} values, expected ${STANDARD_NODE_IDS.size}",
    )
  }

  val state = requireGood(values[0], "Server_ServerStatus_State")
  val currentTime = requireGood(values[1], "Server_ServerStatus_CurrentTime")

  return StandardReadValues(
      serverState = normalizeServerState(state.value.value),
      currentTime = normalizeCurrentTime(currentTime.value.value),
  )
}

private fun requireGood(value: DataValue, nodeName: String): DataValue {
  if (!value.statusCode.isGood) {
    throw UaException(value.statusCode, "standard read failed for $nodeName")
  }
  return value
}

private fun normalizeServerState(value: Any?): String =
    when (value) {
      is ServerState -> value.name
      is Number -> ServerState.from(value.toInt())?.name ?: value.toString()
      else -> value.toString()
    }

private fun normalizeCurrentTime(value: Any?): String =
    when (value) {
      is DateTime -> value.toIso8601String()
      else -> value.toString()
    }

private fun <T> awaitConnection(future: CompletableFuture<T>): T =
    try {
      future.get(CONNECT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
    } catch (e: TimeoutException) {
      future.cancel(true)
      throw TimeoutException("connection attempt timed out after ${CONNECT_TIMEOUT.seconds}s")
          .apply { initCause(e) }
    }

private fun disconnectQuietly(client: OpcUaClient?) {
  if (client == null) return
  try {
    client.disconnectAsync().get(DISCONNECT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
  } catch (_: Exception) {}
}

private fun configureTransport(builder: OpcTcpClientTransportConfigBuilder) {
  builder.setConnectTimeout(uint(REQUEST_TIMEOUT_MILLIS))
  builder.setAcknowledgeTimeout(uint(REQUEST_TIMEOUT_MILLIS))
}

private fun elapsedSince(startedAtNanos: Long): Duration =
    Duration.ofNanos(System.nanoTime() - startedAtNanos)

private fun isPolicyModeCandidate(policy: SecurityPolicy, mode: MessageSecurityMode): Boolean =
    if (policy == SecurityPolicy.None) {
      mode == MessageSecurityMode.None
    } else {
      mode == MessageSecurityMode.Sign || mode == MessageSecurityMode.SignAndEncrypt
    }

private fun thumbprint(certificate: ByteString?): String? {
  if (certificate == null || certificate.isNullOrEmpty) return null
  val decoded = CertificateUtil.decodeCertificate(certificate.bytesOrEmpty())
  return HEX.formatHex(CertificateUtil.thumbprint(decoded).bytesOrEmpty())
}

private val SESSION_FAILURE_STATUS_CODES =
    setOf(
        StatusCodes.Bad_UserAccessDenied,
        StatusCodes.Bad_UserSignatureInvalid,
        StatusCodes.Bad_IdentityTokenInvalid,
        StatusCodes.Bad_IdentityTokenRejected,
        StatusCodes.Bad_IdentityChangeNotSupported,
        StatusCodes.Bad_SessionIdInvalid,
        StatusCodes.Bad_SessionClosed,
        StatusCodes.Bad_SessionNotActivated,
    )

private fun classifyConnectionFailure(failure: Throwable): ProbeFailureCategory {
  val status = UaExceptionStatus.extract(unwrap(failure))
  if (status.isPresent && status.get().statusCode.value in SESSION_FAILURE_STATUS_CODES) {
    // Milo reports session-activation problems through the same failed connect future used for
    // secure-channel errors, so OPC UA status codes provide the useful split for the report.
    return ProbeFailureCategory.SESSION_ACTIVATION_FAILURE
  }

  return ProbeFailureCategory.SECURE_CHANNEL_FAILURE
}

private fun describeFailure(failure: Throwable): String {
  val cause = unwrap(failure)
  val status = UaExceptionStatus.extract(cause)
  if (status.isPresent) {
    val value = status.get().statusCode.value
    val name = StatusCodes.lookup(value).map { parts -> parts[0] }.orElse(value.toString())
    return "$name: ${status.get().message}"
  }

  val message = cause.message
  return if (message.isNullOrBlank()) cause::class.simpleName ?: "failure"
  else "${cause::class.simpleName}: $message"
}

private fun unwrap(failure: Throwable): Throwable {
  var cause = failure
  while ((cause is ExecutionException || cause is CompletionException) && cause.cause != null) {
    cause = cause.cause!!
  }
  return cause
}

private data class CombinationKey(
    val securityPolicy: SecurityPolicy,
    val messageSecurityMode: MessageSecurityMode,
    val userTokenPolicy: String,
)
