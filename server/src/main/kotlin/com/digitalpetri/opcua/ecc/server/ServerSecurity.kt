package com.digitalpetri.opcua.ecc.server

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPair
import java.security.Security
import java.security.cert.X509Certificate
import java.util.HexFormat
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.eclipse.milo.opcua.sdk.server.EndpointCertificateConfig
import org.eclipse.milo.opcua.sdk.server.EndpointConfig
import org.eclipse.milo.opcua.sdk.server.OpcUaServer
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig
import org.eclipse.milo.opcua.sdk.server.identity.AnonymousIdentityValidator
import org.eclipse.milo.opcua.sdk.server.identity.CompositeValidator
import org.eclipse.milo.opcua.sdk.server.identity.IdentityValidator
import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator
import org.eclipse.milo.opcua.stack.core.NodeIds
import org.eclipse.milo.opcua.stack.core.Stack
import org.eclipse.milo.opcua.stack.core.security.AbstractCertificateFactory
import org.eclipse.milo.opcua.stack.core.security.CertificateValidator
import org.eclipse.milo.opcua.stack.core.security.DefaultApplicationGroup
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager
import org.eclipse.milo.opcua.stack.core.security.KeyStoreCertificateStore
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateQuarantine
import org.eclipse.milo.opcua.stack.core.security.MemoryTrustListManager
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy
import org.eclipse.milo.opcua.stack.core.util.CertificateUtil
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder
import org.eclipse.milo.opcua.stack.transport.server.OpcServerTransport
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransport
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransportConfig

private const val PRODUCT_URI = "urn:eclipse:milo:ecc-demo:server"
private val HEX: HexFormat = HexFormat.of()

/**
 * Certificate subject information used for every local server application certificate.
 *
 * Milo creates one certificate per supported application certificate type. The fields here describe
 * the shared application identity; the certificate type determines the key algorithm and curve.
 */
internal data class ServerCertificateConfig(
    val applicationUri: String,
    val commonName: String,
    val organization: String,
    val dnsNames: List<String>,
    val ipAddresses: List<String>,
)

/**
 * Terminal-safe view of a generated local application certificate.
 *
 * The certificate type explains which OPC UA application certificate profile the certificate
 * satisfies, while the thumbprint gives a compact value to compare with advertised endpoints.
 */
internal data class ServerCertificateSummary(
    val certificateTypeId: NodeId,
    val certificateType: String,
    val thumbprint: String,
)

/**
 * Terminal-safe view of one advertised endpoint/user-token combination.
 *
 * OPC UA clients choose an endpoint by matching URL, security policy, message security mode, and
 * user token policy. This summary keeps those fields together so the startup table mirrors the
 * choices a client sees during discovery.
 */
internal data class ServerEndpointSummary(
    val endpointUrl: String,
    val securityPolicy: String,
    val messageSecurityMode: String,
    val userTokens: List<String>,
    val certificateType: String?,
    val certificateThumbprint: String?,
)

/**
 * Snapshot of the server once Milo has started.
 *
 * This is the stable data model for startup output: the endpoint matrix, local identity store,
 * trust behavior, and runtime versions.
 */
internal data class ServerStartupSummary(
    val endpointCount: Int,
    val endpoints: List<ServerEndpointSummary>,
    val certificates: List<ServerCertificateSummary>,
    val keyStorePath: Path,
    val remoteCertificatesAutoTrusted: Boolean,
    val connectionRateLimitDisabled: Boolean,
    val miloSdkVersion: String,
    val miloStackVersion: String,
)

/**
 * Owns the server's local OPC UA application identity.
 *
 * Callers keep this context open for the lifetime of the server runtime. Closing it releases the
 * underlying keystore; the only persisted file is the server's own application identity under the
 * configured data directory.
 */
internal class ServerCertificateContext(
    val certificateManager: DefaultCertificateManager,
    val applicationGroup: DefaultApplicationGroup,
    private val certificateStore: KeyStoreCertificateStore,
    val keyStorePath: Path,
) : AutoCloseable {
  override fun close() {
    certificateStore.close()
  }
}

/**
 * Owns the Milo server, demo namespace, and certificate context as one lifecycle.
 *
 * Use [create] to build a runtime, call [start] to make endpoints available, and close the runtime
 * when the process is shutting down. The runtime starts the namespace before the server so clients
 * can read the demo nodes as soon as the endpoint accepts sessions.
 */
internal class ServerRuntime
private constructor(
    private val certificateContext: ServerCertificateContext,
    private val server: OpcUaServer,
    private val namespace: DemoNamespace,
) : AutoCloseable {
  private var namespaceStarted = false
  private var serverStarted = false
  private var closed = false

  /** Starts the namespace and server, then returns a snapshot suitable for terminal output. */
  fun start(): ServerStartupSummary {
    check(!closed) { "server runtime has been closed" }
    if (!namespaceStarted) {
      namespace.startup()
      namespaceStarted = true
    }
    if (!serverStarted) {
      server.startup().get()
      serverStarted = true
    }

    return startupSummary()
  }

  override fun close() {
    if (closed) return

    var failure: Exception? = null

    if (namespaceStarted) {
      try {
        namespace.shutdown()
      } catch (e: Exception) {
        failure = e
      } finally {
        namespaceStarted = false
      }
    }

    if (serverStarted) {
      try {
        server.shutdown().get()
      } catch (e: Exception) {
        failure = failure?.also { it.addSuppressed(e) } ?: e
      } finally {
        serverStarted = false
      }
    }

    try {
      certificateContext.close()
    } catch (e: Exception) {
      failure = failure?.also { it.addSuppressed(e) } ?: e
    } finally {
      closed = true
    }

    failure?.let { throw it }
  }

  private fun startupSummary(): ServerStartupSummary {
    val certificatesByRawBytes = certificateLookup(certificateContext.applicationGroup)
    val endpoints =
        server.applicationContext.endpointDescriptions.map { endpoint ->
          endpointSummary(endpoint, certificatesByRawBytes)
        }

    return ServerStartupSummary(
        endpointCount = endpoints.size,
        endpoints = endpoints,
        certificates = certificatesByRawBytes.values.toList(),
        keyStorePath = certificateContext.keyStorePath,
        remoteCertificatesAutoTrusted = true,
        connectionRateLimitDisabled = true,
        miloSdkVersion = OpcUaServer.SDK_VERSION,
        miloStackVersion = Stack.VERSION,
    )
  }

  companion object {
    /** Creates a server runtime from command-line options without starting network listeners. */
    fun create(options: ServerOptions): ServerRuntime {
      registerBouncyCastle()
      disableConnectionRateLimit()

      val certificateContext = initializeServerCertificates(options)
      try {
        val endpointMatrix = buildEndpointMatrix(options)
        val serverConfig = serverConfig(options, certificateContext, endpointMatrix)
        val server = OpcUaServer(serverConfig, ::createTransport)
        val namespace = DemoNamespace(server)

        return ServerRuntime(certificateContext, server, namespace)
      } catch (e: Exception) {
        certificateContext.close()
        throw e
      }
    }
  }
}

/**
 * The full set of endpoint definitions requested from Milo.
 *
 * [requests] preserves the human-readable matrix rows, while [endpointConfigs] contains the
 * de-duplicated Milo endpoint configuration objects passed to the server.
 */
internal data class EndpointMatrix(
    val requests: List<EndpointRequest>,
    val endpointConfigs: Set<EndpointConfig>,
)

/**
 * One desired OPC UA endpoint advertisement.
 *
 * A client must match the endpoint address, security policy, message security mode, and one of the
 * user token policies before it can open a secure channel and activate a session.
 */
internal data class EndpointRequest(
    val bindAddress: String,
    val port: Int,
    val endpointAddress: String,
    val securityPolicy: SecurityPolicy,
    val messageSecurityMode: MessageSecurityMode,
    val userTokenPolicies: List<UserTokenPolicy>,
)

/**
 * Creates the server certificate set required by the ECC interoperability profile.
 *
 * Milo asks this factory for certificate chains by OPC UA application certificate type. Each chain
 * is self-signed because the demo focuses on endpoint compatibility rather than PKI administration.
 */
private class InteropCertificateFactory(
    private val config: ServerCertificateConfig,
) : AbstractCertificateFactory() {
  override fun createRsaSha256CertificateChain(keyPair: KeyPair): Array<X509Certificate> =
      buildChain(SelfSignedCertificateBuilder(keyPair))

  override fun createEccNistP256CertificateChain(keyPair: KeyPair) = ecc(keyPair)

  override fun createEccNistP384CertificateChain(keyPair: KeyPair) = ecc(keyPair)

  override fun createEccBrainpoolP256r1CertificateChain(keyPair: KeyPair) = ecc(keyPair)

  override fun createEccBrainpoolP384r1CertificateChain(keyPair: KeyPair) = ecc(keyPair)

  override fun createEccCurve25519CertificateChain(keyPair: KeyPair) = ecc(keyPair)

  override fun createEccCurve448CertificateChain(keyPair: KeyPair) = ecc(keyPair)

  private fun ecc(keyPair: KeyPair): Array<X509Certificate> =
      buildChain(SelfSignedCertificateBuilder.forEccApplicationCertificate(keyPair))

  private fun buildChain(builder: SelfSignedCertificateBuilder): Array<X509Certificate> {
    builder
        .setApplicationUri(config.applicationUri)
        .setCommonName(config.commonName)
        .setOrganization(config.organization)

    config.dnsNames.forEach(builder::addDnsName)
    config.ipAddresses.forEach(builder::addIpAddress)

    return arrayOf(builder.build())
  }
}

private fun initializeServerCertificates(options: ServerOptions): ServerCertificateContext {
  val keyStorePath = Path.of(options.dataDir).resolve("own").resolve("application.p12").normalize()
  Files.createDirectories(keyStorePath.parent)

  val certificateStore =
      KeyStoreCertificateStore.createAndInitialize(
          KeyStoreCertificateStore.Settings(
              keyStorePath,
              { keyStorePassword() },
              { _: String -> keyStorePassword() },
          ),
      )

  // Milo still expects trust-list and quarantine collaborators. Keep both in memory so this demo
  // persists only the local application identity under <data-dir>/own/application.p12.
  val trustListManager = MemoryTrustListManager()
  val certificateQuarantine = MemoryCertificateQuarantine()
  val certificateValidator = QuietInsecureCertificateValidator
  val applicationGroup =
      DefaultApplicationGroup.createAndInitialize(
          trustListManager,
          certificateStore,
          InteropCertificateFactory(
              ServerCertificateConfig(
                  applicationUri = options.applicationUri,
                  commonName = options.applicationName,
                  organization = "Eclipse Milo",
                  dnsNames = options.dnsNames,
                  ipAddresses = options.ipAddresses,
              ),
          ),
          certificateValidator,
          REQUIRED_APPLICATION_CERTIFICATE_TYPE_IDS,
      )
  val certificateManager = DefaultCertificateManager(certificateQuarantine, applicationGroup)

  return ServerCertificateContext(
      certificateManager = certificateManager,
      applicationGroup = applicationGroup,
      certificateStore = certificateStore,
      keyStorePath = keyStorePath,
  )
}

private object QuietInsecureCertificateValidator : CertificateValidator {
  override fun validateCertificateChain(
      certificateChain: MutableList<X509Certificate>,
      applicationUri: String?,
      validHostnames: Array<out String?>?,
  ) {
    // Deliberately trust remote certificates for this interoperability demo.
  }
}

/** Application certificate profiles needed to advertise the full interoperability matrix. */
private val REQUIRED_APPLICATION_CERTIFICATE_TYPE_IDS =
    listOf(
        NodeIds.RsaSha256ApplicationCertificateType,
        NodeIds.EccNistP256ApplicationCertificateType,
        NodeIds.EccNistP384ApplicationCertificateType,
        NodeIds.EccBrainpoolP256r1ApplicationCertificateType,
        NodeIds.EccBrainpoolP384r1ApplicationCertificateType,
        NodeIds.EccCurve25519ApplicationCertificateType,
        NodeIds.EccCurve448ApplicationCertificateType,
    )

/** Short certificate type labels used in startup output. */
private val CERTIFICATE_TYPE_NAMES =
    mapOf(
        NodeIds.RsaSha256ApplicationCertificateType to "RsaSha256",
        NodeIds.EccNistP256ApplicationCertificateType to "EccNistP256",
        NodeIds.EccNistP384ApplicationCertificateType to "EccNistP384",
        NodeIds.EccBrainpoolP256r1ApplicationCertificateType to "EccBrainpoolP256r1",
        NodeIds.EccBrainpoolP384r1ApplicationCertificateType to "EccBrainpoolP384r1",
        NodeIds.EccCurve25519ApplicationCertificateType to "EccCurve25519",
        NodeIds.EccCurve448ApplicationCertificateType to "EccCurve448",
    )

private fun buildEndpointMatrix(options: ServerOptions): EndpointMatrix {
  val requests = mutableListOf<EndpointRequest>()
  val endpointConfigs = linkedSetOf<EndpointConfig>()
  val securityPolicies = options.policies.map(SecurityPolicy::valueOf)
  val messageModes = options.modes.map(MessageSecurityMode::valueOf)

  // The endpoint matrix is the server-side contract clients discover: every bind/advertised
  // address pair gets each valid policy/mode combination and each configured user token.
  for (bindAddress in options.bindAddresses) {
    for (endpointAddress in options.endpointAddresses) {
      for (securityPolicy in securityPolicies) {
        for (messageMode in requestedModes(securityPolicy, messageModes)) {
          val request =
              EndpointRequest(
                  bindAddress = bindAddress,
                  port = options.port,
                  endpointAddress = endpointAddress,
                  securityPolicy = securityPolicy,
                  messageSecurityMode = messageMode,
                  userTokenPolicies = userTokenPolicies(securityPolicy, options.tokens),
              )

          requests += request
          endpointConfigs += endpointConfig(request)
        }
      }
    }
  }

  return EndpointMatrix(requests, endpointConfigs)
}

private fun requestedModes(
    securityPolicy: SecurityPolicy,
    configuredModes: List<MessageSecurityMode>,
): List<MessageSecurityMode> {
  if (securityPolicy == SecurityPolicy.None) {
    return configuredModes.filter { it == MessageSecurityMode.None }
  }

  return configuredModes.filter { it != MessageSecurityMode.None }
}

private fun endpointConfig(request: EndpointRequest): EndpointConfig {
  val builder =
      EndpointConfig.newBuilder()
          .setBindAddress(request.bindAddress)
          .setBindPort(request.port)
          .setHostname(request.endpointAddress)
          .setSecurityPolicy(request.securityPolicy)
          .setSecurityMode(request.messageSecurityMode)
          .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)

  if (request.securityPolicy != SecurityPolicy.None) {
    builder.setEndpointCertificateConfig(EndpointCertificateConfig.newBuilder().build())
  }

  request.userTokenPolicies.forEach(builder::addTokenPolicy)

  return builder.build()
}

private fun userTokenPolicies(
    endpointSecurityPolicy: SecurityPolicy,
    configuredTokens: List<String>,
): List<UserTokenPolicy> =
    configuredTokens.map { token ->
      when (token) {
        "Anonymous" -> UserTokenPolicy("anonymous", UserTokenType.Anonymous, null, null, null)
        "UserName" -> {
          // Username tokens can name their own security policy. In this demo they inherit the
          // endpoint policy whenever messages are protected, which keeps discovery easy to read.
          val securityPolicyUri =
              endpointSecurityPolicy.takeUnless { it == SecurityPolicy.None }?.uri
          UserTokenPolicy("username", UserTokenType.UserName, null, null, securityPolicyUri)
        }
        else -> error("unsupported token: $token")
      }
    }

private fun serverConfig(
    options: ServerOptions,
    certificateContext: ServerCertificateContext,
    endpointMatrix: EndpointMatrix,
): OpcUaServerConfig =
    OpcUaServerConfig.builder()
        .setApplicationUri(options.applicationUri)
        .setApplicationName(LocalizedText.english(options.applicationName))
        .setProductUri(PRODUCT_URI)
        .setBuildInfo(
            BuildInfo(
                PRODUCT_URI,
                "digitalpetri",
                "ecc-demo-server",
                "0.1.0-SNAPSHOT",
                Stack.VERSION,
                DateTime.now(),
            ),
        )
        .setCertificateManager(certificateContext.certificateManager)
        .setIdentityValidator(identityValidator(options))
        .setEndpoints(endpointMatrix.endpointConfigs)
        .build()

private fun identityValidator(options: ServerOptions): IdentityValidator {
  val validators = mutableListOf<IdentityValidator>()

  if ("Anonymous" in options.tokens) {
    validators += AnonymousIdentityValidator.INSTANCE
  }

  if ("UserName" in options.tokens) {
    validators += UsernameIdentityValidator { challenge ->
      challenge.username == options.username && challenge.password == options.password
    }
  }

  return CompositeValidator(validators)
}

private fun createTransport(transportProfile: TransportProfile): OpcServerTransport {
  require(transportProfile == TransportProfile.TCP_UASC_UABINARY) {
    "unsupported transport profile: $transportProfile"
  }

  return OpcTcpServerTransport(OpcTcpServerTransportConfig.newBuilder().build())
}

private fun certificateLookup(
    applicationGroup: DefaultApplicationGroup
): Map<ByteString, ServerCertificateSummary> =
    applicationGroup.certificateEntries.associate { entry ->
      val certificate = entry.certificateChain[0]
      ByteString.of(certificate.encoded) to
          ServerCertificateSummary(
              certificateTypeId = entry.certificateTypeId,
              certificateType =
                  CERTIFICATE_TYPE_NAMES[entry.certificateTypeId]
                      ?: entry.certificateTypeId.toParseableString(),
              thumbprint = thumbprint(certificate),
          )
    }

private fun endpointSummary(
    endpoint: EndpointDescription,
    certificatesByRawBytes: Map<ByteString, ServerCertificateSummary>,
): ServerEndpointSummary {
  val securityPolicyUri: String = endpoint.securityPolicyUri ?: ""
  val certificate =
      endpoint.serverCertificate?.takeUnless { it.isNullOrEmpty }?.let(certificatesByRawBytes::get)
  val userTokens =
      endpoint.userIdentityTokens?.map {
        if (it.tokenType == UserTokenType.UserName) "UserName" else it.tokenType.name
      } ?: emptyList()
  val securityPolicyName =
      SecurityPolicy.fromUriSafe(securityPolicyUri).map { it.name }.orElse(securityPolicyUri)

  return ServerEndpointSummary(
      endpointUrl = endpoint.endpointUrl ?: "",
      securityPolicy = securityPolicyName,
      messageSecurityMode = endpoint.securityMode.name,
      userTokens = userTokens.distinct(),
      certificateType = certificate?.certificateType,
      certificateThumbprint = certificate?.thumbprint,
  )
}

private fun thumbprint(certificate: X509Certificate): String =
    HEX.formatHex(CertificateUtil.thumbprint(certificate).bytesOrEmpty())

private fun keyStorePassword(): CharArray = "ecc-demo-server".toCharArray()

private fun registerBouncyCastle() {
  if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
    Security.addProvider(BouncyCastleProvider())
  }
}

private fun disableConnectionRateLimit() {
  Stack.ConnectionLimits.RATE_LIMIT_ENABLED = false
}
