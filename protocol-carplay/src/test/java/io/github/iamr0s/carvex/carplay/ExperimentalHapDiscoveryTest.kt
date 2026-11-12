package io.github.iamr0s.carvex.carplay

import io.github.iamr0s.carvex.carplay.core.*
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress

class ExperimentalHapDiscoveryTest {
    private val binding=SecurityBinding(4,"session-peer",9)
    private val auth=BootstrapAuthentication(4,9,2,false,challengeSignatureVerified=true)
    private val address=InetAddress.getByName("192.0.2.1")
    private val metadata=ReceiverMetadata("synthetic-pair-id",ByteArray(32){7},1UL shl 38,
        endpoint=address,port=7000,deviceId="02:11:22:33:44:55")
    private fun bootstrap()=WifiBootstrap("synthetic","password1",2,null,authentication=auth)
        .resolved("192.0.2.1",7000,requireNotNull(metadata.deviceId),metadata.publicKey,metadata)

    @Test fun explicitExperimentCanReachPairedFromCurrentScopedDiscoveryWithoutFakingStartReady(){
        val config=bootstrap()
        val input=config.securityInputs(binding,metadata,true,true,experimentalIntegrityOnly=true)
        assertEquals(SecurityEntry.DISCOVERY,input.endpointSource)
        assertFalse(input.startReady)
        assertFalse(config.authentication!!.aaTrusted)
        assertEquals(true,input.pairedCapabilityGate)
        assertEquals(SecurityRoute.PAIRED,SecurityRouter.route(input))
        // The gate opens a candidate; it neither supplies an SRP input nor activates a record.
        assertEquals(SecurityReason.SETUP_INPUT_UNAVAILABLE,assertThrows(SecurityFailure::class.java){
            SecurityRouter.select(input)
        }.diagnostic.localReason)
    }
    @Test fun normalPolicyAndExplicitGateAreNotChangedByTheExperimentCandidate(){
        val normal=bootstrap().securityInputs(binding,metadata,true,true)
        assertNull(normal.pairedCapabilityGate)
        assertEquals(SecurityReason.SECURITY_POLICY_UNRESOLVED,assertThrows(SecurityFailure::class.java){
            SecurityRouter.route(normal)
        }.diagnostic.localReason)
        val disabled=bootstrap().securityInputs(binding,metadata,true,true,pairedCapabilityGate=false,experimentalIntegrityOnly=true)
        assertEquals(SecurityRoute.SAP,SecurityRouter.route(disabled))
        val noBit=bootstrap().securityInputs(binding,metadata.copy(features=0UL),true,true,experimentalIntegrityOnly=true)
        assertNull(noBit.pairedCapabilityGate)
        assertEquals(SecurityRoute.SAP,SecurityRouter.route(noBit))
        val missing=bootstrap().securityInputs(binding,metadata.copy(features=null),true,true,experimentalIntegrityOnly=true)
        assertEquals(SecurityReason.SECURITY_INPUT_MISSING,assertThrows(SecurityFailure::class.java){
            SecurityRouter.route(missing)
        }.diagnostic.localReason)
    }
    @Test fun malformedOrMisboundDiscoveryNeverSelectsTheCompatibilityGate(){
        // Malformed identity hints and mismatched endpoints stay rejected.
        for(meta in listOf(metadata.copy(pairingId=" "),
            metadata.copy(pairingId="x".repeat(1025)),metadata.copy(publicKey=ByteArray(31)),
            metadata.copy(pairingId=null,publicKey=ByteArray(32){7}),
            metadata.copy(endpoint=null),metadata.copy(endpoint=InetAddress.getByName("192.0.2.2")),
            metadata.copy(port=7001),
            metadata.copy(deviceId="02:66:77:88:99:AA"))){
            val input=bootstrap().securityInputs(binding,meta,true,true,experimentalIntegrityOnly=true)
            assertNull(input.pairedCapabilityGate)
            assertEquals(SecurityReason.SECURITY_POLICY_UNRESOLVED,assertThrows(SecurityFailure::class.java){
                SecurityRouter.route(input)
            }.diagnostic.localReason)
        }
        for(config in listOf(bootstrap().copy(authentication=auth.copy(challengeSignatureVerified=false)),
            bootstrap().copy(bootstrapTransport=SecurityTransport.USB_BOOTSTRAP_NCM))){
            assertNull(config.securityInputs(binding,metadata,true,true,experimentalIntegrityOnly=true).pairedCapabilityGate)
        }
        assertNull(bootstrap().securityInputs(binding,metadata,false,true,experimentalIntegrityOnly=true).pairedCapabilityGate)
        assertNull(bootstrap().securityInputs(binding,metadata,true,false,experimentalIntegrityOnly=true).pairedCapabilityGate)
    }
    @Test fun discoveryWithoutPairingIdentifierOrKeyIsACandidateAndLearnsIdentityDuringSetup(){
        // CarPlay _airplay._tcp on a VW/MIB head unit carries neither pi nor pk. Bonjour still
        // proves the endpoint, so the gate must let it through and Pair Setup binds the identity.
        val noHints=metadata.copy(pairingId=null,publicKey=null)
        val input=bootstrap().securityInputs(binding,noHints,true,true,experimentalIntegrityOnly=true)
        assertEquals(true,input.pairedCapabilityGate)
        assertEquals(SecurityRoute.PAIRED,SecurityRouter.route(input))
        assertTrue(ExperimentalHapDiscovery.identityLearnedDuringSetup(noHints))
        // A missing deviceid does not by itself disqualify an otherwise bound endpoint.
        val noDeviceId=metadata.copy(deviceId=null)
        assertEquals(true,bootstrap().securityInputs(binding,noDeviceId,true,true,experimentalIntegrityOnly=true).pairedCapabilityGate)
        // The fully bound shape keeps working and does not need the learn-during-setup route.
        val complete=bootstrap().securityInputs(binding,metadata,true,true,experimentalIntegrityOnly=true)
        assertEquals(true,complete.pairedCapabilityGate)
        assertFalse(ExperimentalHapDiscovery.identityLearnedDuringSetup(metadata))
    }
    @Test fun staleSourceCannotUseTheExperimentalProfileEvenWithMatchingMetadata(){
        for(stale in listOf(binding.copy(generation=3),binding.copy(epoch=8))){
            assertEquals(SecurityReason.STALE_CONTEXT,assertThrows(SecurityFailure::class.java){
                SecurityRouter.route(bootstrap().securityInputs(stale,metadata,true,true,experimentalIntegrityOnly=true))
            }.diagnostic.localReason)
        }
        assertEquals(SecurityReason.STALE_CONTEXT,assertThrows(SecurityFailure::class.java){
            bootstrap().securityInputs(binding,metadata,true,true,experimentalIntegrityOnly=true,sourceContextCurrent=false)
        }.diagnostic.localReason)
    }
}
