package io.github.iamr0s.carvex.carplay

import io.github.iamr0s.carvex.carplay.core.*

/** Successful source-Link trust is a separate gate from candidate AirPlay routing. */
internal fun WifiBootstrap.requireAuthenticatedBootstrap(experimentalIntegrityOnly:Boolean=false) {
    if (authentication?.accepted(experimentalIntegrityOnly) != true) SecurityRequirements.requireAaTrust()
}

/** The production caller passes the binding saved before endpoint discovery. */
fun WifiBootstrap.securityInputs(
    expectedBinding: SecurityBinding, metadata: ReceiverMetadata,
    networkReady: Boolean, endpointValidated: Boolean, pairedCapabilityGate: Boolean? = null,
    experimentalIntegrityOnly: Boolean = false,
    sourceContextCurrent: Boolean = true,
): SecurityInputs {
    if(!sourceContextCurrent)securityFailure(SecurityReason.STALE_CONTEXT,phase="bootstrap-context")
    val source = authentication ?: securityFailure(SecurityReason.SECURITY_INPUT_MISSING,phase="bootstrap-context")
    val endpoint = endpoint ?: securityFailure(SecurityReason.SECURITY_INPUT_MISSING,phase="endpoint-resolution")
    val binding = expectedBinding.copy(generation=source.generation,epoch=source.epoch)
    // The user's explicit v11 experiment permits a bounded HAP attempt after scoped
    // discovery too. This local profile is not a peer capability or production trust.
    val gate=pairedCapabilityGate ?: ExperimentalHapDiscovery.gate(this,metadata,expectedBinding,
        networkReady,endpointValidated,experimentalIntegrityOnly)
    return SecurityInputs(binding, expectedBinding=expectedBinding, controlVersion=source.controlVersion,
        bootstrapTransport=bootstrapTransport, endpointSource=endpoint.source,
        startReady=startSessionReady, bootstrapAuthenticationAccepted=source.accepted(experimentalIntegrityOnly),
        networkReady=networkReady, endpointValidated=endpointValidated,
        features=metadata.effectiveFeatures, pairedCapabilityGate=gate,
        peerHintPresent=metadata.pairingId?.isNotEmpty()==true || startSessionReady,
        setupProviderBound=false, featureEvidence=metadata.effectiveFeatureEvidence)
}

/** A candidate only: setup/verify, historical key pins and live epoch gates remain mandatory. */
internal object ExperimentalHapDiscovery {
    fun gate(config:WifiBootstrap,metadata:ReceiverMetadata,binding:SecurityBinding,
             networkReady:Boolean,endpointValidated:Boolean,enabled:Boolean):Boolean? {
        if(!enabled||config.startSessionReady||config.bootstrapTransport!=SecurityTransport.BLUETOOTH_WIFI||
            config.endpointSource!=SecurityEntry.DISCOVERY||!networkReady||!endpointValidated)return null
        val auth=config.authentication?:return null
        if(auth.generation!=binding.generation||auth.epoch!=binding.epoch||!auth.challengeSignatureVerified)return null
        // CarPlay receivers that run CarPlay over HAP advertise feature bit 38 (direct CoreUtils
        // pairing). That bit is what makes this candidate meaningful at all.
        if(metadata.effectiveFeatureEvidence.has(38)!=true)return null
        val endpoint=config.endpoint?:return null
        if(metadata.endpoint==null||metadata.port!=endpoint.port)return null
        val sameAddress=runCatching{metadata.endpoint.address.contentEquals(IpLiteral.parse(endpoint.address).address.address)}.getOrDefault(false)
        if(!sameAddress)return null
        val device=metadata.deviceId
        if(device!=null){
            val samePeer=runCatching{ReceiverIdentity.canonical(device)==ReceiverIdentity.canonical(endpoint.receiver)}.getOrDefault(false)
            if(!samePeer)return null
        }
        // Two discovery shapes reach this point:
        //  * HAP-style TXT carrying pi (pairing identifier) and pk (public key): the candidate can
        //    be bound to a stored peer before pairing, which is the strongest evidence shape.
        //  * CarPlay _airplay._tcp advertising neither pi nor pk — what a VW/MIB head unit does
        //    (observed log line "keyPresent=false"). Here Bonjour only yields the endpoint; the
        //    peer identity is learned from the Pair Setup reply itself, exactly like the
        //    4301-only fallback already implemented in AirSession.
        // Demanding pi here made that second shape permanently unroutable
        // (SECURITY_POLICY_UNRESOLVED), so this gate now only rejects *malformed* identity hints
        // instead of requiring bound identity. Identity binding is still enforced afterwards by
        // PairingIdentityBinding, the stored-record lookup and HomeKit's advertised-key check.
        val pi=metadata.pairingId
        val key=metadata.publicKey
        val piMalformed=pi!=null&&(pi.isBlank()||pi.toByteArray(Charsets.UTF_8).size !in 1..1024)
        val keyMalformed=key!=null&&key.size!=32
        if(piMalformed||keyMalformed||(pi==null&&key!=null))return null
        return true
    }

    /** True when Bonjour exposed no pairing identifier or no public key, so the peer identity has
     * to be learned from the Pair Setup exchange itself instead of being bound beforehand. */
    fun identityLearnedDuringSetup(metadata:ReceiverMetadata):Boolean {
        val pi=metadata.pairingId
        return pi==null||pi.isBlank()||metadata.publicKey?.size!=32
    }
}
