package com.digitalpetri.opcua.ecc.client

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPair
import java.security.Security
import java.security.cert.X509Certificate
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.eclipse.milo.opcua.stack.core.NodeIds
import org.eclipse.milo.opcua.stack.core.security.*
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder

internal const val CLIENT_APPLICATION_URI = "urn:eclipse:milo:ecc-demo:client"

/**
 * Owns the client's local OPC UA application identity for one probe run.
 *
 * Milo uses the certificate manager when opening secure channels and the certificate validator when
 * handling remote server certificates and username-token encryption. Closing this context releases
 * the local keystore; the demo intentionally persists only the client's own identity.
 */
internal data class ClientSecurityContext(
    val keyStorePath: Path,
    val applicationGroup: DefaultApplicationGroup,
    val certificateManager: DefaultCertificateManager,
    val certificateValidator: CertificateValidator,
    private val certificateStore: KeyStoreCertificateStore,
) : AutoCloseable {
  override fun close() {
    certificateStore.close()
  }
}

/**
 * Creates or opens the client's local application certificates.
 *
 * The client needs application certificates even when it is probing many different servers because
 * OPC UA secure channels identify both peers. The validator auto-trusts remote certificates, so
 * interoperability failures are about endpoint compatibility, credentials, or reads rather than
 * local trust-list setup.
 */
internal fun initializeClientSecurity(options: ClientOptions): ClientSecurityContext {
  registerBouncyCastle()

  val keyStorePath = Path.of(options.dataDir).resolve("own").resolve("application.p12").normalize()
  Files.createDirectories(keyStorePath.parent)

  val certificateStore =
      ClientKeyStoreCertificateStore.createAndInitialize(
          keyStorePath,
          { keyStorePassword() },
          { _: String -> keyStorePassword() },
      )
  // Keep the trust-list and rejected-certificate state in memory. The demo reports auto-trust in
  // the terminal instead of teaching operators to manage persistent trust directories.
  val certificateValidator = QuietInsecureCertificateValidator
  val applicationGroup =
      DefaultApplicationGroup.createAndInitialize(
          MemoryTrustListManager(),
          certificateStore,
          ClientApplicationCertificateFactory(),
          certificateValidator,
          REQUIRED_APPLICATION_CERTIFICATE_TYPE_IDS,
      )
  val certificateManager =
      DefaultCertificateManager(MemoryCertificateQuarantine(), applicationGroup)

  return ClientSecurityContext(
      keyStorePath = keyStorePath,
      applicationGroup = applicationGroup,
      certificateManager = certificateManager,
      certificateValidator = certificateValidator,
      certificateStore = certificateStore,
  )
}

/** Certificate validator that accepts every remote certificate for demo interoperability runs. */
private object QuietInsecureCertificateValidator : CertificateValidator {
  override fun validateCertificateChain(
      certificateChain: MutableList<X509Certificate>,
      applicationUri: String?,
      validHostnames: Array<out String?>?,
  ) {
    // Deliberately trust remote certificates for this interoperability demo.
  }
}

/**
 * Creates one client application certificate for each certificate type used by the probe profile.
 *
 * The certificates all share the same application URI and subject fields; Milo chooses the key
 * algorithm from the certificate factory method it calls.
 */
private class ClientApplicationCertificateFactory : AbstractCertificateFactory() {
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
    val certificate =
        builder
            .setCommonName("ECC Demo Probe Client")
            .setOrganization("Eclipse Milo")
            .setOrganizationalUnit("interop")
            .setLocalityName("Folsom")
            .setStateName("CA")
            .setCountryCode("US")
            .setApplicationUri(CLIENT_APPLICATION_URI)
            .addDnsName("localhost")
            .addIpAddress("127.0.0.1")
            .build()

    return arrayOf(certificate)
  }
}

/**
 * Keystore adapter that gives each client certificate type a stable alias.
 *
 * Stable aliases make repeated probe runs reuse the same local identity instead of producing new
 * certificates whenever the process starts.
 */
private class ClientKeyStoreCertificateStore
private constructor(
    settings: Settings,
) : KeyStoreCertificateStore(settings) {
  override fun getAlias(certificateTypeId: NodeId): String =
      when (certificateTypeId) {
        NodeIds.RsaSha256ApplicationCertificateType -> "client-ai"
        NodeIds.EccNistP256ApplicationCertificateType -> "client-ecc-nistp256"
        NodeIds.EccNistP384ApplicationCertificateType -> "client-ecc-nistp384"
        NodeIds.EccBrainpoolP256r1ApplicationCertificateType -> "client-ecc-brainpoolp256r1"
        NodeIds.EccBrainpoolP384r1ApplicationCertificateType -> "client-ecc-brainpoolp384r1"
        NodeIds.EccCurve25519ApplicationCertificateType -> "client-ecc-curve25519"
        NodeIds.EccCurve448ApplicationCertificateType -> "client-ecc-curve448"
        else -> certificateTypeId.toParseableString()
      }

  override fun getPreloadedCertificateTypeIds(): List<NodeId> =
      REQUIRED_APPLICATION_CERTIFICATE_TYPE_IDS

  companion object {
    fun createAndInitialize(
        keyStorePath: Path,
        keyStorePasswordSupplier: () -> CharArray,
        aliasPasswordSupplier: (String) -> CharArray,
    ): ClientKeyStoreCertificateStore {
      val store =
          ClientKeyStoreCertificateStore(
              Settings(keyStorePath, keyStorePasswordSupplier, aliasPasswordSupplier),
          )
      store.initialize()
      return store
    }
  }
}

/** Application certificate profiles needed to probe the full interoperability matrix. */
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

private fun keyStorePassword(): CharArray = "ecc-demo-client".toCharArray()

private fun registerBouncyCastle() {
  if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
    Security.addProvider(BouncyCastleProvider())
  }
}
