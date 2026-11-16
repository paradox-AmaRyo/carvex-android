package io.github.iamr0s.carvex.carplay

import io.github.iamr0s.carvex.carplay.core.*
import org.junit.Assert.*
import org.junit.Test
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.ExecutionException

/** Synthetic ACC at the real ByteStream/Link/CSM boundary; no Android or secret fixtures. */
class BootstrapNegotiationTest {
    private class Peer(val version:Int):AutoCloseable {
        val phoneIn=PipedInputStream(32768)
        val carOut=PipedOutputStream(phoneIn)
        val carIn=PipedInputStream(32768)
        val phoneOut=PipedOutputStream(carIn)
        @Volatile var failMessage:Int?=null
        private val outputFrames=java.util.concurrent.CopyOnWriteArrayList<IapWire.Frame>()
        /** These short transactions do not wrap PSNs. A retransmission keeps its
         *  sequence/session/payload; a new transaction with the same ID does not. */
        val outputAttempts:List<Int> get(){
            val logical=mutableListOf<IapWire.Frame>()
            for(frame in outputFrames){
                if(logical.none{it.seq==frame.seq&&it.session==frame.session&&
                    it.payload.contentEquals(frame.payload)})logical+=frame
            }
            return logical.map{IapWire.u16(it.payload,4)}
        }
        private val output=object:java.io.OutputStream(){
            override fun write(value:Int)=phoneOut.write(value)
            override fun write(bytes:ByteArray,offset:Int,length:Int){
                val packet=bytes.copyOfRange(offset,offset+length)
                val frame=runCatching{IapWire.read(java.io.ByteArrayInputStream(packet))}.getOrNull()
                if(frame!=null&&frame.session==17&&frame.payload.size>=6){
                    val id=IapWire.u16(frame.payload,4)
                    // Preserve even the failed write; only the assertion view deduplicates retries.
                    outputFrames+=frame.copy(payload=frame.payload.copyOf())
                    if(id==failMessage)throw java.io.IOException("synthetic output failure")
                }
                phoneOut.write(bytes,offset,length)
            }
            override fun flush()=phoneOut.flush()
            override fun close()=phoneOut.close()
        }
        val link=IapLink(phoneIn,output,{},{})
        val worker=Executors.newSingleThreadExecutor()
        var seq=40
        var hostSeq=0
        fun initialize(){
            val work=worker.submit {
                val sync=byteArrayOf(1,1)+IapWire.be16(2048)+IapWire.be16(100)+IapWire.be16(10)+
                    byteArrayOf(2,1,17,0,version.toByte())
                carOut.write(IapWire.packet(IapWire.Frame(0x80,seq,0,0,sync)));carOut.flush()
                val reply=IapWire.read(carIn);hostSeq=reply.seq
                ack(reply.seq)
            }
            link.start(allowDirectSyn=true)
            work.get(3,TimeUnit.SECONDS)
        }
        fun ack(ack:Int){carOut.write(IapWire.packet(IapWire.Frame(0x40,seq,ack,0,byteArrayOf())));carOut.flush()}
        fun command(id:Int,fields:List<Pair<Int,ByteArray>> = emptyList()){
            seq=(seq+1) and 255
            // Send exactly the supplied fields: a missing-field test must not be repaired here.
            carOut.write(IapWire.packet(IapWire.Frame(0x40,seq,hostSeq,17,IapWire.csm(id,fields))));carOut.flush()
        }
        fun next():Pair<Int,IapFields> {
            while(true){
                val frame=IapWire.read(carIn)
                if(frame.payload.isEmpty())continue
                hostSeq=frame.seq;ack(frame.seq)
                assertEquals(17,frame.session)
                assertTrue(frame.payload.size>=6)
                val id=IapWire.u16(frame.payload,4)
                // 4E0C（deviceUUID）现在识别后无条件发送；本文件不针对它断言，ACK 后跳过，
                // 让各用例仍按"下一条业务消息"读取。
                if(id==0x4e0c)continue
                return id to IapWire.parseFieldList(frame.payload.copyOfRange(6,frame.payload.size))
            }
        }
        /** 4E0C 现在无条件先发；跳过与本次断言无关的前置消息。 */
        fun nextOf(id:Int):Pair<Int,IapFields>{
            while(true){val m=next();if(m.first==id)return m}
        }
        /** Read the next CSM message, including 4E0C. A delayed link ACK can
         * precede it; it is not a CSM message and must not be ACKed again. */
        fun nextRaw():Pair<Int,IapFields> {
            while(true){
                val frame=IapWire.read(carIn)
                if(frame.flags==0x40&&frame.session==0&&frame.payload.isEmpty())continue
                hostSeq=frame.seq;ack(frame.seq)
                assertEquals(17,frame.session)
                assertTrue(frame.payload.size>=6)
                return IapWire.u16(frame.payload,4) to IapWire.parseFieldList(frame.payload.copyOfRange(6,frame.payload.size))
            }
        }
        val logs=java.util.concurrent.CopyOnWriteArrayList<String>()
        val awaitingStart=java.util.concurrent.CountDownLatch(1)
        var onBootstrapLog:((String)->Unit)?=null
        fun negotiate(handoffWaitMs:Long=30_000L,onDigitalKeyRequest:DigitalKeyMatcher?=null,
                      onDeviceWifiInfoRequest:DeviceWifiInfoProvider?=null,
                      onCarPlayStartRequest:CarPlayStartRequest?=null,
                      onWifiAnnouncement:WifiAnnouncementHandler?=null,
                      identificationWaitMs:Long=10_000L,
                      networkHandoff:IapNetworkHandoff?=null)=worker.submit<WifiBootstrap> {
            Bootstrap.negotiate(link,"02:11:22:33:44:55","synthetic",PairIdentity("synthetic",ByteArray(32)),
                experimentalIntegrityOnly=true,handoffWaitMs=handoffWaitMs,log={message->
                    logs+=message
                    if(message.startsWith("5703 received; awaiting requested 4301"))awaitingStart.countDown()
                    onBootstrapLog?.invoke(message)
                },onDigitalKeyRequest=onDigitalKeyRequest,onDeviceWifiInfoRequest=onDeviceWifiInfoRequest,
                onCarPlayStartRequest=onCarPlayStartRequest,onWifiAnnouncement=onWifiAnnouncement,
                identificationWaitMs=identificationWaitMs,networkHandoff=networkHandoff)
        }
        override fun close(){link.close();carOut.close();carIn.close();worker.shutdownNow()}
    }

    @Test(timeout=5000) fun rawMessageReaderSkipsPureAckButKeepsDeviceUuidMessage(){
        Peer(2).use{peer->
            peer.phoneOut.write(IapWire.packet(IapWire.Frame(0x40,7,40,0,byteArrayOf())))
            peer.phoneOut.write(IapWire.packet(IapWire.Frame(0x40,8,40,17,IapWire.csm(0x4e0c,emptyList()))))
            peer.phoneOut.flush()
            assertEquals(0x4e0c,peer.nextRaw().first)
            assertEquals(8,peer.hostSeq)
            val ack=IapWire.read(peer.phoneIn)
            assertEquals(8,ack.ack)
            assertEquals(0,peer.phoneIn.available()) // No ACK-of-ACK was generated.
        }
    }

    /** Explicit initial-message fixture; power fields 8/9 are registered, not unknown strings. */
    private fun identification(sends:ByteArray=byteArrayOf(0x57,3),receives:ByteArray=byteArrayOf(0x57,2),transport:Int=17)=listOf(
        0 to IapWire.cstring("synthetic-accessory"),1 to IapWire.cstring("synthetic-model"),
        2 to IapWire.cstring("synthetic-maker"),3 to IapWire.cstring("synthetic-serial"),
        4 to IapWire.cstring("firmware-1"),5 to IapWire.cstring("hardware-1"),
        6 to sends,7 to receives,8 to byteArrayOf(0),9 to IapWire.be16(100),
        12 to IapWire.cstring("en"),13 to IapWire.cstring("en"),
        transport to IapWire.fields(listOf(0 to IapWire.be16(0),1 to IapWire.cstring("synthetic-transport"))+
            if(transport==17)listOf(3 to ByteArray(6))else listOf(4 to byteArrayOf())))

    private fun assertNoApplicationOutput(peer:Peer){
        while(peer.carIn.available()>0){
            assertTrue("only transport ACKs may remain",IapWire.read(peer.carIn).payload.isEmpty())
        }
    }

    /** Minimal self-signed synthetic certificate, built in memory; no trusted credential fixture. */
    private class SyntheticAccessory(private val rsa:Boolean=false) {
        val pair=if(rsa)KeyPairGenerator.getInstance("RSA").apply{initialize(1024)}.generateKeyPair()
            else KeyPairGenerator.getInstance("EC").apply{initialize(java.security.spec.ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private fun der(tag:Int,bytes:ByteArray):ByteArray {
            val size=bytes.size
            val length=if(size<128)byteArrayOf(size.toByte()) else if(size<=255)
                byteArrayOf(0x81.toByte(),size.toByte()) else byteArrayOf(0x82.toByte(),(size ushr 8).toByte(),size.toByte())
            return byteArrayOf(tag.toByte())+length+bytes
        }
        private fun hex(value:String)=value.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
        val certificate:ByteArray by lazy {
            val algorithm=hex(if(rsa)"300d06092a864886f70d01010b0500"else "300a06082a8648ce3d040302")
            val name=der(0x30,der(0x31,der(0x30,hex("0603550403")+der(0x0c,"synthetic test".toByteArray()))))
            val validity=der(0x30,der(0x17,"250101000000Z".toByteArray())+der(0x17,"350101000000Z".toByteArray()))
            val tbs=der(0x30,hex("a003020102")+der(2,hex("0102030405060708090a0b0c0d0e0f10"))+algorithm+name+validity+name+pair.public.encoded)
            val signature=Signature.getInstance(if(rsa)"SHA256withRSA"else "SHA256withECDSA").run{initSign(pair.private);update(tbs);sign()}
            val cert=der(0x30,tbs+algorithm+der(3,byteArrayOf(0)+signature))
            // DER PKCS#7 signedData certificate container, no signerInfo. No trust is asserted.
            der(0x30,hex("06092a864886f70d010702")+der(0xa0,der(0x30,
                hex("0201013100")+der(0x30,hex("06092a864886f70d010701"))+der(0xa0,cert)+hex("3100"))))
        }
        fun sign(challenge:ByteArray):ByteArray=Signature.getInstance(if(rsa)"NONEwithRSA"else "NONEwithECDSAinP1363Format").run {
            initSign(pair.private)
            update(if(rsa)hex("3021300906052b0e03021a05000414")+challenge else challenge)
            sign()
        }
    }

    @Test(timeout=10000) fun productionEntryReportsAaLayerInsteadOfBluetoothProfileRejection() {
        Peer(2).use { peer ->
            peer.initialize()
            val error=assertThrows(SecurityFailure::class.java){
                Bootstrap.negotiate(peer.link,"02:11:22:33:44:55","synthetic",PairIdentity("synthetic",ByteArray(32)),log={})
            }
            assertEquals(SecurityReason.AA_TRUST_MATERIAL_UNAVAILABLE,error.diagnostic.localReason)
            assertEquals("iAP2-AA",error.diagnostic.layer)
            assertEquals("certificate-verification",error.diagnostic.phase)
            assertEquals(0,peer.carIn.available()) // No AA success or authentication request was fabricated.
        }
    }

    @Test(timeout=10000) fun versionOneStartsAuthenticationAndRejectsRemoteFailure() {
        Peer(1).use { peer ->
            peer.initialize()
            val work=peer.negotiate()
            val request=peer.next()
            assertEquals(0xaa00,request.first);assertTrue(request.second.isEmpty())
            peer.command(0xaa04)
            assertTrue(assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause is SecurityException)
        }
    }

    @Test(timeout=15000) fun experimentalRsaDigestAuthenticationPrecedesIdentifyAnd5703OnlyHandoff() {
        Peer(1).use { peer ->
            val accessory=SyntheticAccessory(rsa=true)
            peer.initialize()
            val work=peer.negotiate()
            val request=peer.next()
            assertEquals(0xaa00,request.first);assertTrue(request.second.isEmpty())
            peer.command(0xaa01,listOf(0 to accessory.certificate))
            val challenge=peer.next()
            assertEquals(0xaa02,challenge.first)
            val digest=requireNotNull(challenge.second[0]);assertEquals(20,digest.size)
            val signature=accessory.sign(digest);assertEquals(128,signature.size)
            peer.command(0xaa03,listOf(0 to signature))
            assertEquals(0xaa05,peer.next().first)
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification())
            assertEquals(0x1d02,peer.next().first)
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x5703,wifiAnnouncement(security=2))
            val result=work.get(3,TimeUnit.SECONDS)
            assertNull(result.endpoint)
            assertFalse(result.startSessionReady)
            assertEquals(2,result.security)
            assertTrue(requireNotNull(result.authentication).challengeSignatureVerified)
            assertFalse(requireNotNull(result.authentication).aaTrusted)
            // Experimental integrity is not promoted to production trust.
            assertThrows(SecurityFailure::class.java){result.requireAuthenticatedBootstrap()}
        }
    }

    @Test(timeout=10000) fun experimentalRsaBadSignatureTerminatesWithoutAlternateChallengeOrIdentify() {
        Peer(1).use { peer ->
            val accessory=SyntheticAccessory(rsa=true)
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0xaa00,peer.next().first)
            peer.command(0xaa01,listOf(0 to accessory.certificate))
            val challenge=peer.next();assertEquals(0xaa02,challenge.first)
            val digest=requireNotNull(challenge.second[0]);assertEquals(20,digest.size)
            val invalid=accessory.sign(digest).apply{this[0]=(this[0].toInt() xor 1).toByte()}
            peer.command(0xaa03,listOf(0 to invalid))
            assertEquals(0xaa04,peer.next().first)
            assertTrue(assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause is SecurityException)
            // Read the last transport ACK then prove no extra AA02 or 1D00 was issued.
            while(peer.carIn.available()>0)assertTrue(IapWire.read(peer.carIn).payload.isEmpty())
        }
    }

    @Test(timeout=10000) fun malformedAa01EmitsAa04BeforeTerminating() {
        Peer(1).use { peer ->
            val accessory=SyntheticAccessory()
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0xaa00,peer.next().first)
            // Raw mode is a one-byte field; the firmware reports this transaction
            // failure in-band before the local session is terminated.
            peer.command(0xaa01,listOf(0 to accessory.certificate,1 to byteArrayOf(0,0)))
            assertEquals(0xaa04,peer.next().first)
            assertTrue(assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause is SecurityException)
        }
    }

    @Test(timeout=15000) fun aa01ModeTwoKeepsPublicCertificateFlow() {
        Peer(1).use { peer ->
            val accessory=SyntheticAccessory()
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0xaa00,peer.next().first)
            // 24A446 logs the invalid auth type but leaves its internal auth
            // type at 0, so the transaction continues through public auth.
            peer.command(0xaa01,listOf(0 to accessory.certificate,1 to byteArrayOf(2)))
            val challenge=peer.next()
            assertEquals(0xaa02,challenge.first)
            peer.command(0xaa03,listOf(0 to accessory.sign(requireNotNull(challenge.second[0]))))
            assertEquals(0xaa05,peer.next().first)
            work.cancel(true)
        }
    }

    @Test(timeout=10000) fun aa01ModeOneRejectsInvalidBaaChainInBand() {
        Peer(1).use { peer ->
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0xaa00,peer.next().first)
            peer.command(0xaa01,listOf(
                0 to byteArrayOf(1),
                1 to byteArrayOf(1),
                2 to byteArrayOf(2),
            ))
            assertEquals(0xaa04,peer.next().first)
            val cause=assertThrows(ExecutionException::class.java){
                work.get(3,TimeUnit.SECONDS)
            }.cause
            assertTrue(cause is SecurityException)
            assertTrue(requireNotNull(cause).message!!.contains("BAA authentication chain rejected"))
        }
    }

    @Test(timeout=10000) fun missingAa03SignatureEmitsAa04BeforeTerminating() {
        Peer(1).use { peer ->
            val accessory=SyntheticAccessory()
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0xaa00,peer.next().first)
            peer.command(0xaa01,listOf(0 to accessory.certificate))
            assertEquals(0xaa02,peer.next().first)
            peer.command(0xaa03)
            assertEquals(0xaa04,peer.next().first)
            assertTrue(assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause is IllegalArgumentException)
        }
    }

    @Test(timeout=15000) fun digitalKeyRequestUsesMatcherAndEmitsOnlyMatched4303() {
        Peer(1).use { peer ->
            val accessory=SyntheticAccessory()
            peer.initialize()
            val work=peer.negotiate(onDigitalKeyRequest={ids ->
                assertEquals(listOf("requested-a","requested-b"),ids)
                listOf("matched-key")
            })
            assertEquals(0xaa00,peer.next().first)
            peer.command(0xaa01,listOf(0 to accessory.certificate))
            val challenge=peer.next();assertEquals(0xaa02,challenge.first)
            peer.command(0xaa03,listOf(0 to accessory.sign(requireNotNull(challenge.second[0]))))
            assertEquals(0xaa05,peer.next().first)
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification(byteArrayOf(0x43,2,0x43,1),byteArrayOf(0x43,0)))
            assertEquals(0x1d02,peer.next().first)
            peer.nextOf(0x4300)
            peer.command(0x4302,listOf(0 to IapWire.cstring("requested-a"),0 to IapWire.cstring("requested-b")))
            val result=peer.nextOf(0x4303)
            assertEquals(listOf("matched-key"),result.second.ordered.map{IapWire.text(it.second)})
            work.cancel(true)
        }
    }

    @Test(timeout=15000) fun digitalKeyRequestWithoutMatcherDoesNotFabricate4303() {
        Peer(1).use { peer ->
            val accessory=SyntheticAccessory()
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0xaa00,peer.next().first)
            peer.command(0xaa01,listOf(0 to accessory.certificate))
            val challenge=peer.next();assertEquals(0xaa02,challenge.first)
            peer.command(0xaa03,listOf(0 to accessory.sign(requireNotNull(challenge.second[0]))))
            assertEquals(0xaa05,peer.next().first)
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification(byteArrayOf(0x43,2,0x43,1),byteArrayOf(0x43,0)))
            assertEquals(0x1d02,peer.next().first)
            peer.nextOf(0x4300)
            peer.command(0x4302,listOf(0 to IapWire.cstring("requested")))
            Thread.sleep(100)
            assertFalse(peer.logs.any{it.contains("4303 digital-key result sent")})
            assertFalse(peer.logs.any{it.contains("unknown handshake command 4302")})
            work.cancel(true)
        }
    }

    @Test(timeout=15000) fun rawSixteenByteSerialStillRequestsFullP256CertificateAndVerifiesFreshChallenge() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory()
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification(byteArrayOf(0x57,3,0xaa.toByte(),6)))
            assertEquals(0x1d02,peer.next().first)
            val serialRequest=peer.next()
            assertEquals(0xaa00,serialRequest.first);assertArrayEquals(byteArrayOf(),serialRequest.second[0])
            peer.command(0xaa06,listOf(0 to ByteArray(16){(it+0x60).toByte()}))
            val fullCertificateRequest=peer.next()
            assertEquals(0xaa00,fullCertificateRequest.first);assertTrue(fullCertificateRequest.second.isEmpty())
            peer.command(0xaa01,listOf(0 to accessory.certificate))
            val challenge=peer.next();assertEquals(0xaa02,challenge.first)
            val digest=requireNotNull(challenge.second[0]);assertEquals(32,digest.size)
            assertFalse(work.isDone)
            peer.command(0xaa03,listOf(0 to accessory.sign(digest)))
            assertEquals(0xaa05,peer.next().first)
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x5703,wifiAnnouncement(security=2))
            assertTrue(requireNotNull(work.get(3,TimeUnit.SECONDS).authentication).challengeSignatureVerified)
        }
    }

    @Test(timeout=10000) fun versionTwoIdentifyCapabilitiesChangeTheActualCertificateRequest() {
        Peer(2).use { peer ->
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification(byteArrayOf(0x43,1,0xaa.toByte(),6),byteArrayOf(0x43,0)))
            assertEquals(0x1d02,peer.next().first)
            val certificate=peer.next()
            assertEquals(0xaa00,certificate.first)
            assertArrayEquals(byteArrayOf(),certificate.second[0])
            peer.command(0xaa04)
            assertTrue(assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause is SecurityException)
        }
    }

    @Test(timeout=10000) fun earlyWifiConfigAndRemoteSuccessCannotCompleteAuthentication() {
        Peer(1).use { peer ->
            peer.initialize()
            peer.command(0x4301)
            peer.command(0xaa05)
            val work=peer.negotiate()
            assertEquals(0xaa00,peer.next().first)
            assertFalse(work.isDone)
            peer.command(0xaa04)
            assertTrue(assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause is SecurityException)
        }
    }

    /** A-0002：识别状态不是 1/3 时收到 0x1D01，固件只记录并忽略，不重跑识别也不断链。 */
    @Test(timeout=10000) fun identificationBeforeItsTransactionIsIgnored() {
        Peer(1).use { peer ->
            peer.initialize()
            peer.command(0x1d01,identification(byteArrayOf(0x43,1),byteArrayOf()))
            peer.negotiate()
            // 认证照常启动；早到的 0x1D01 既没有产生 0x1D02，也没有把链路带走。
            assertEquals(0xaa00,peer.next().first)
            // AA/00 先发、队列里的 1D/01 后处理，日志断言要等它被消费。
            val deadline=System.nanoTime()+2_000_000_000L
            while(System.nanoTime()<deadline&&peer.logs.none{it.startsWith("iAP 1d01 ignored")})Thread.sleep(10)
            assertTrue("logs="+peer.logs,peer.logs.any{it.startsWith("iAP 1d01 ignored")})
        }
    }

    @Test(timeout=15000) fun no5702PeerCanCompleteUsingLater4301AfterRealSignatureVerification() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory()
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification(byteArrayOf(0x43,1,0xaa.toByte(),1,0xaa.toByte(),3,0xaa.toByte(),6),byteArrayOf(0x43,0)))
            assertEquals(0x1d02,peer.next().first)
            assertEquals(0xaa00,peer.next().first)
            peer.command(0xaa06,listOf(0 to "0102030405060708090A0B0C0D0E0F10".toByteArray()))
            val fullCertificateRequest=peer.next()
            assertEquals(0xaa00,fullCertificateRequest.first);assertTrue(fullCertificateRequest.second.isEmpty())
            peer.command(0xaa01,listOf(0 to accessory.certificate))
            val challenge=peer.next()
            assertEquals(0xaa02,challenge.first)
            peer.command(0xaa03,listOf(0 to accessory.sign(requireNotNull(challenge.second[0]))))
            assertEquals(0xaa05,peer.next().first)
            assertEquals(0x4300,peer.next().first)
            val wifi=IapWire.fields(listOf(0 to IapWire.cstring("synthetic"),1 to IapWire.cstring("password1"),
                3 to IapWire.cstring("192.168.1.2"),4 to byteArrayOf(2)))
            peer.command(0x4301,listOf(1 to wifi,2 to IapWire.be32(7000),3 to IapWire.cstring("synthetic")))
            assertEquals("synthetic",work.get(3,TimeUnit.SECONDS).ssid)
        }
    }

    @Test(timeout=10000) fun empty4301IsDispatchedAndLaterValidMessageCompletesHandoff() {
        Peer(2).use { peer ->
            val work=beginDualHandoff(peer)

            // 24A446 records the connection event and dispatches an empty 43/01
            // to the platform. It does not invent a local endpoint or tear down
            // the authenticated iAP2 session.
            peer.command(0x4301)
            Thread.sleep(100)
            assertFalse("an empty 4301 must not complete the local handoff",work.isDone)
            assertTrue(peer.logs.any{it.startsWith("4301 connection event received before parse")})
            assertTrue(peer.logs.any{it.startsWith("4301 empty start dispatched to platform")})

            // A retransmitted, valid 43/01 is accepted on the same link.
            peer.command(0x4301,startSession())
            peer.command(0x5703,wifiAnnouncement())
            val result=work.get(3,TimeUnit.SECONDS)
            assertEquals("192.0.2.1",result.address)
            assertTrue(result.startSessionReady)
        }
    }
    @Test(timeout=10000) fun partial4301IsDispatchedWithoutInventingEndpoint() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val dispatched=java.util.concurrent.CountDownLatch(1)
            val work=peer.negotiate(onCarPlayStartRequest={dispatched.countDown()})
            authenticateV2(peer,accessory,byteArrayOf(0x43,1),byteArrayOf(0x43,0))
            peer.nextOf(0x4300)
            peer.command(0x4301,listOf(1 to IapWire.fields(emptyList())))
            assertTrue(peer.logs.joinToString(" | "),dispatched.await(2,TimeUnit.SECONDS))
            assertFalse(work.isDone)
            peer.command(0x4301,startSession())
            val result=work.get(3,TimeUnit.SECONDS)
            assertEquals("192.0.2.1",result.address)
        }
    }
    @Test(timeout=10000) fun partial4301WithLaterMalformedKnownFieldNeverReachesPlatform() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val callbacks=java.util.concurrent.atomic.AtomicInteger()
            val rejected=java.util.concurrent.CountDownLatch(1)
            peer.onBootstrapLog={if(it.startsWith("4301 rejected: field=2"))rejected.countDown()}
            val work=peer.negotiate(onCarPlayStartRequest={callbacks.incrementAndGet()})
            authenticateV2(peer,accessory,byteArrayOf(0x43,1),byteArrayOf(0x43,0))
            peer.nextOf(0x4300)
            peer.command(0x4301,listOf(1 to IapWire.fields(emptyList()),2 to byteArrayOf(1)))
            assertTrue(rejected.await(2,TimeUnit.SECONDS));assertEquals(0,callbacks.get());assertFalse(work.isDone)
            peer.command(0x4301,startSession()+listOf(2 to IapWire.be32(7001)))
            assertEquals(7001,work.get(3,TimeUnit.SECONDS).port)
            assertEquals(1,callbacks.get())
            assertEquals(1,peer.outputAttempts.count{it==0x1d00})
            assertEquals(1,peer.outputAttempts.count{it==0xaa00})
        }
    }
    @Test(timeout=10000) fun malformedChannelRejectsWholeStartAndLaterSameLinkMessageSucceeds() {
        Peer(2).use { peer ->
            val work=beginDualHandoff(peer)
            val bad=startSession()+listOf(1 to IapWire.fields(listOf(2 to byteArrayOf(0,6))))
            peer.command(0x4301,bad)
            peer.command(0x4301,startSession()+listOf(1 to IapWire.fields(listOf(2 to byteArrayOf(6)))))
            peer.command(0x5703,wifiAnnouncement())
            assertEquals("192.0.2.1",work.get(3,TimeUnit.SECONDS).address)
            assertTrue(peer.logs.any{it.startsWith("4301 rejected: field=1.2")})
        }
    }
    @Test(timeout=10000) fun syntacticallyValidButLocallyUnusableStartStillReachesPlatform() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val callbacks=java.util.concurrent.atomic.AtomicInteger()
            val dispatched=java.util.concurrent.CountDownLatch(1)
            val work=peer.negotiate(onCarPlayStartRequest={callbacks.incrementAndGet();dispatched.countDown()})
            authenticateV2(peer,accessory,byteArrayOf(0x43,1),byteArrayOf(0x43,0))
            peer.nextOf(0x4300)
            peer.command(0x4301,startSession()+listOf(2 to IapWire.be32(0)))
            assertTrue(dispatched.await(2,TimeUnit.SECONDS));assertFalse(work.isDone)
            peer.command(0x4301,startSession())
            assertEquals(7000,work.get(3,TimeUnit.SECONDS).port)
            assertEquals(2,callbacks.get())
        }
    }
    @Test(timeout=10000) fun partial5703DoesNotPrematurelyTerminateNetworkOnlyHandoff() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val partial=java.util.concurrent.CountDownLatch(1)
            val work=peer.negotiate(onWifiAnnouncement={if(it?.ssid==null)partial.countDown()})
            authenticateV2(peer,accessory,byteArrayOf(0x57,3),byteArrayOf(0x57,2))
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x5703,listOf(4 to byteArrayOf(6)))
            assertTrue(partial.await(2,TimeUnit.SECONDS));assertFalse(work.isDone)
            peer.command(0x5703,wifiAnnouncement(security=2))
            val result=work.get(3,TimeUnit.SECONDS)
            assertNull(result.endpoint);assertEquals("synthetic",result.ssid)
        }
    }
    @Test(timeout=10000) fun invalid5703TerminationNeverReachesPlatformButValidReplacementDoes() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val callbacks=java.util.concurrent.atomic.AtomicInteger()
            val work=peer.negotiate(onWifiAnnouncement={callbacks.incrementAndGet()})
            authenticateV2(peer,accessory,byteArrayOf(0x57,3),byteArrayOf(0x57,2))
            peer.nextOf(0x5702)
            peer.command(0x5703,listOf(1 to byteArrayOf(65,0,66))+wifiAnnouncement(security=2))
            peer.command(0x5703,wifiAnnouncement(security=2))
            assertEquals("synthetic",work.get(3,TimeUnit.SECONDS).ssid)
            assertEquals(1,callbacks.get())
        }
    }
    @Test(timeout=10000) fun partial5703UsesOriginalDeadlineAndReportsMissingCredentialField() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate(handoffWaitMs=500)
            authenticateV2(peer,accessory,byteArrayOf(0x57,3),byteArrayOf(0x57,2))
            peer.nextOf(0x5702)
            peer.command(0x5703,listOf(4 to byteArrayOf(6)))
            val error=assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause
            assertTrue(error is WifiConfigurationException)
            assertEquals(1,(error as WifiConfigurationException).fieldId)
            assertEquals(WifiConfigurationProblem.MISSING_FIELD,error.problem)
        }
    }
    private fun authenticateV2(peer:Peer,accessory:SyntheticAccessory,sends:ByteArray,receives:ByteArray,transport:Int=17) {
        assertEquals(0x1d00,peer.next().first)
        peer.command(0x1d01,identification(sends,receives,transport))
        assertEquals(0x1d02,peer.next().first)
        finishAuthenticationV2(peer,accessory)
    }
    private fun finishAuthenticationV2(peer:Peer,accessory:SyntheticAccessory) {
        assertEquals(0xaa00,peer.next().first)
        peer.command(0xaa01,listOf(0 to accessory.certificate))
        val challenge=peer.next();assertEquals(0xaa02,challenge.first)
        peer.command(0xaa03,listOf(0 to accessory.sign(requireNotNull(challenge.second[0]))))
        assertEquals(0xaa05,peer.next().first)
    }
    @Test(timeout=15000) fun mylinkDeclarationProbeSendsWifiRequestBeforeOptionalIdentity() {
        Peer(2).use { peer ->
            peer.initialize()
            val work=peer.negotiate()
            val accessory=SyntheticAccessory()
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification(byteArrayOf(0x57,3,0xaa.toByte(),6),
                byteArrayOf(0x4e,0x0d,0x4e,0x0e,0x57,2)))
            assertEquals(0x1d02,peer.next().first)
            assertEquals(0xaa00,peer.next().first)
            peer.command(0xaa06,listOf(0 to ByteArray(16){(it+0x60).toByte()}))
            assertEquals(0xaa00,peer.next().first)
            peer.command(0xaa01,listOf(0 to accessory.certificate))
            val challenge=peer.next();assertEquals(0xaa02,challenge.first)
            peer.command(0xaa03,listOf(0 to accessory.sign(requireNotNull(challenge.second[0]))))
            assertEquals(0xaa05,peer.next().first)
            // Read wire order, not nextOf: the latter would conceal the regression.
            assertEquals(0x5702,peer.nextRaw().first)
            assertEquals(0x4e0e,peer.nextRaw().first)
            assertEquals(0x4e0d,peer.nextRaw().first)
            assertEquals(0x4e0c,peer.nextRaw().first)
            peer.command(0x5703,listOf(1 to IapWire.cstring("synthetic"),2 to IapWire.cstring("password1"),
                4 to byteArrayOf(6),3 to byteArrayOf(2)))
            assertEquals("synthetic",work.get(3,TimeUnit.SECONDS).ssid)
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=15000) fun wifiAnnouncementOnlyRequestsDiscoveryWithoutInventingAnEndpoint() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate()
            authenticateV2(peer,accessory,byteArrayOf(0x57,3),byteArrayOf(0x57,2))
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x5703,listOf(1 to IapWire.cstring("synthetic"),2 to IapWire.cstring("password1"),
                4 to byteArrayOf(6),3 to byteArrayOf(2)))
            val result=work.get(3,TimeUnit.SECONDS)
            assertEquals("synthetic",result.ssid);assertNull(result.endpoint)
            assertFalse(result.startSessionReady)
            assertEquals(SecurityEntry.DISCOVERY,result.endpointSource)
            assertFalse(result.authentication!!.aaTrusted) // Synthetic math is not production AA.
            assertTrue(result.authentication!!.challengeSignatureVerified)
            result.requireAuthenticatedBootstrap(experimentalIntegrityOnly=true)
            val metadata=ReceiverMetadata("pair-id",null,0UL)
            val resolved=result.resolved("192.0.2.1",7000,"02:11:22:33:44:55",null,metadata)
            val binding=SecurityBinding(peer.link.generation,"synthetic-session",peer.link.linkEpoch)
            val inputs=resolved.securityInputs(binding,metadata,true,true)
            assertEquals(SecurityTransport.BLUETOOTH_WIFI,inputs.bootstrapTransport)
            assertEquals(SecurityEntry.DISCOVERY,inputs.endpointSource)
            assertFalse(inputs.startReady)
            assertEquals(SecurityRoute.SAP,SecurityRouter.route(inputs))
            // End-to-end production execution still cannot promote the synthetic AA result.
            assertEquals(SecurityReason.AA_TRUST_MATERIAL_UNAVAILABLE,
                assertThrows(SecurityFailure::class.java){resolved.requireAuthenticatedBootstrap()}.diagnostic.localReason)
        }
    }

    @Test(timeout=10000) fun deviceWifiRequestDoesNotEmitSynthetic5701WithoutPlatformConsent() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate()
            // Advertise both halves of the device-information pair and the accessory
            // pair so the request can be exercised in an otherwise valid session.
            authenticateV2(peer,accessory,
                byteArrayOf(0x57,3,0x57,0),
                byteArrayOf(0x57,2,0x57,1))
            assertEquals(0x5702,peer.nextOf(0x5702).first)

            peer.command(0x5700)
            Thread.sleep(100)
            // The link ACK is allowed; no application 5701 response may be fabricated.
            while(peer.carIn.available()>0){
                val frame=IapWire.read(peer.carIn)
                assertTrue("5700 without consent must not emit a 5701 payload",frame.payload.isEmpty())
            }
            assertTrue(peer.logs.any{it.contains("no 5701 emitted")})

            // Continue with the independent accessory Wi-Fi path to prove the session
            // itself remains usable after the unanswered 5700.
            peer.command(0x5703,wifiAnnouncement(security=2))
            assertNull(work.get(3,TimeUnit.SECONDS).endpoint)
        }
    }

    @Test(timeout=15000) fun declared5700UsesWifiProviderAndEncodesStatusAndOptionalFields() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate(onDeviceWifiInfoRequest={
                DeviceWifiInfo(status=0,security=2,ssid="synthetic",passphrase="password1")
            })
            authenticateV2(peer,accessory,
                byteArrayOf(0x57,0),byteArrayOf(0x57,1))
            peer.command(0x5700)
            val response=peer.nextOf(0x5701)
            assertEquals(0,requireNotNull(response.second[0])[0].toInt())
            assertEquals(2,requireNotNull(response.second[1])[0].toInt())
            assertEquals("synthetic",IapWire.text(requireNotNull(response.second[2])))
            assertEquals("password1",IapWire.text(requireNotNull(response.second[3])))
            work.cancel(true)
        }
    }

    @Test(timeout=15000) fun wifiProviderStatusOneOmitsOptionalCredentials() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate(onDeviceWifiInfoRequest={DeviceWifiInfo(status=1,security=2,ssid="ignored",passphrase="ignored")})
            authenticateV2(peer,accessory,
                byteArrayOf(0x57,0),byteArrayOf(0x57,1))
            peer.command(0x5700)
            val response=peer.nextOf(0x5701)
            assertEquals(1,requireNotNull(response.second[0])[0].toInt())
            assertEquals(listOf(0),response.second.ordered.map{it.first})
            work.cancel(true)
        }
    }

    @Test(timeout=15000) fun wifiProviderStatusTwoOmitsOptionalCredentials() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate(onDeviceWifiInfoRequest={DeviceWifiInfo(status=2,security=2,ssid="ignored",passphrase="ignored")})
            authenticateV2(peer,accessory,
                byteArrayOf(0x57,0),byteArrayOf(0x57,1))
            peer.command(0x5700)
            val response=peer.nextOf(0x5701)
            assertEquals(2,requireNotNull(response.second[0])[0].toInt())
            assertEquals(listOf(0),response.second.ordered.map{it.first})
            work.cancel(true)
        }
    }
    @Test(timeout=10000) fun empty5703IsDispatchedWithoutInventingWifiCredentials() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val dispatched=java.util.concurrent.CountDownLatch(1)
            var empty:Boolean?=null
            val work=peer.negotiate(onWifiAnnouncement={announcement -> empty=announcement==null;dispatched.countDown()})
            authenticateV2(peer,accessory,byteArrayOf(0x57,3),byteArrayOf(0x57,2))
            peer.nextOf(0x5702)
            peer.command(0x5703)
            assertTrue(peer.logs.joinToString(" | "),dispatched.await(2,TimeUnit.SECONDS))
            assertEquals(true,empty)
            assertFalse(work.isDone)
            work.cancel(true)
        }
    }

    @Test(timeout=10000) fun empty4301IsDispatchedWithoutInventingEndpoint() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val dispatched=java.util.concurrent.CountDownLatch(1)
            var empty:Boolean?=null
            val work=peer.negotiate(onCarPlayStartRequest={fields -> empty=fields.isEmpty();dispatched.countDown()})
            authenticateV2(peer,accessory,byteArrayOf(0x43,1),byteArrayOf(0x43,0))
            peer.nextOf(0x4300)
            peer.command(0x4301)
            assertTrue(peer.logs.joinToString(" | "),dispatched.await(2,TimeUnit.SECONDS))
            assertEquals(true,empty)
            assertFalse(work.isDone)
            work.cancel(true)
        }
    }

    private fun wifiAnnouncement(security:Int=3)=listOf(1 to IapWire.cstring("synthetic"),
        2 to IapWire.cstring("password1"),4 to byteArrayOf(6),3 to byteArrayOf(security.toByte()))
    private fun startSession(password:String="password1")=listOf(
        1 to IapWire.fields(listOf(0 to IapWire.cstring("synthetic"),1 to IapWire.cstring(password),
            3 to IapWire.cstring("192.0.2.1"),4 to byteArrayOf(3))),
        2 to IapWire.be32(7000),3 to IapWire.cstring("synthetic-peer"))
    private fun coordinator(peer:Peer)=IapNetworkHandoff(peer.link.generation,peer.link.linkEpoch,true,{true},peer.logs::add)
    private fun lateCommand(peer:Peer):IapCommand {
        repeat(6){peer.link.poll(500)?.let{return it}}
        error("late iAP message missing")
    }

    @Test(timeout=10000) fun coordinatorReturns5703WithoutWaitingForDeclared4301AndConsumesLateWireMessage() {
        Peer(2).use{peer->
            peer.initialize();val handoff=coordinator(peer)
            val work=peer.negotiate(networkHandoff=handoff)
            authenticateV2(peer,SyntheticAccessory(),byteArrayOf(0x57,3,0x43,1),byteArrayOf(0x57,2,0x43,0))
            peer.nextOf(0x5702);peer.nextOf(0x4300)
            peer.command(0x5703,wifiAnnouncement(security=2))
            val bootstrap=work.get(3,TimeUnit.SECONDS) // Production timeout remains30s, not shortened for this test.
            assertNull(bootstrap.endpoint);handoff.acceptBootstrap(bootstrap)
            peer.command(0x4301,startSession())
            val late=lateCommand(peer)
            assertEquals(0x4301,late.id)
            assertFalse(bootstrap.identification!!.handle(late,peer.link.generation,peer.link.linkEpoch,peer.logs::add))
            assertTrue(handoff.handle(late,peer.link.generation,peer.link.linkEpoch))
            assertEquals("192.0.2.1",handoff.configuration()!!.address)
            assertSame(bootstrap.authentication,handoff.configuration()!!.authentication)
            assertEquals(2,handoff.configuration()!!.security)
        }
    }

    @Test(timeout=10000) fun coordinatorReturnsComplete4301WithoutWaitingFor5703() {
        Peer(2).use{peer->
            peer.initialize();val handoff=coordinator(peer)
            val work=peer.negotiate(networkHandoff=handoff)
            authenticateV2(peer,SyntheticAccessory(),byteArrayOf(0x57,3,0x43,1),byteArrayOf(0x57,2,0x43,0))
            peer.nextOf(0x5702);peer.nextOf(0x4300)
            peer.command(0x4301,startSession())
            val result=work.get(3,TimeUnit.SECONDS)
            assertEquals(7000,result.port);assertTrue(result.startSessionReady)
            handoff.acceptBootstrap(result)
        }
    }

    @Test(timeout=10000) fun coordinatorAcceptsSameMessageNetworkSubsetBeforeEndpoint() {
        Peer(2).use{peer->
            peer.initialize();val handoff=coordinator(peer)
            val work=peer.negotiate(networkHandoff=handoff)
            authenticateV2(peer,SyntheticAccessory(),byteArrayOf(0x43,1),byteArrayOf(0x43,0))
            peer.nextOf(0x4300)
            peer.command(0x4301,listOf(1 to IapWire.fields(listOf(0 to IapWire.cstring("synthetic"),
                1 to IapWire.cstring("password1"),4 to byteArrayOf(3)))))
            val result=work.get(3,TimeUnit.SECONDS)
            assertNull(result.endpoint);assertFalse(result.startSessionReady)
            handoff.acceptBootstrap(result)
            peer.command(0x4301,startSession())
            assertTrue(handoff.handle(lateCommand(peer),peer.link.generation,peer.link.linkEpoch))
            assertEquals(7000,handoff.configuration()!!.port)
        }
    }

    @Test(timeout=10000) fun coordinatorReaderHandoffPreservesAlreadyQueued4301() {
        Peer(2).use{peer->
            peer.initialize();val handoff=coordinator(peer)
            val parsed=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1)
            peer.onBootstrapLog={message->if(message.startsWith("5703 parsed security=")){
                parsed.countDown();assertTrue(release.await(3,TimeUnit.SECONDS))}}
            val work=peer.negotiate(networkHandoff=handoff)
            authenticateV2(peer,SyntheticAccessory(),byteArrayOf(0x57,3,0x43,1),byteArrayOf(0x57,2,0x43,0))
            peer.nextOf(0x5702);peer.nextOf(0x4300)
            try{
                peer.command(0x5703,wifiAnnouncement());assertTrue(parsed.await(2,TimeUnit.SECONDS))
                peer.command(0x4301,startSession())
                var frame=IapWire.read(peer.carIn)
                while(frame.ack!=peer.seq)frame=IapWire.read(peer.carIn)
                assertTrue(frame.payload.isEmpty())
            }finally{release.countDown()}
            val result=work.get(3,TimeUnit.SECONDS);assertNull(result.endpoint)
            handoff.acceptBootstrap(result)
            assertTrue(handoff.handle(lateCommand(peer),peer.link.generation,peer.link.linkEpoch))
            assertEquals("192.0.2.1",handoff.configuration()!!.address)
        }
    }

    @Test(timeout=10000) fun coordinatorRejectsEarlyUnadvertisedAndMalformedInputsBeforeCorrection() {
        Peer(2).use{peer->
            peer.initialize();val handoff=coordinator(peer)
            val work=peer.negotiate(networkHandoff=handoff)
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x5703,wifiAnnouncement());peer.command(0x4301,startSession())
            peer.command(0x1d01,identification(byteArrayOf(0x43,1),byteArrayOf(0x43,0)))
            assertEquals(0x1d02,peer.next().first)
            finishAuthenticationV2(peer,SyntheticAccessory());peer.nextOf(0x4300)
            assertNull(handoff.configuration())
            peer.command(0x5703,wifiAnnouncement()) // Undeclared after authentication.
            peer.command(0x4301,startSession()+listOf(8 to byteArrayOf(2))) // Bad boolean anywhere rejects message.
            peer.command(0x4301,startSession())
            val result=work.get(3,TimeUnit.SECONDS);assertEquals(7000,result.port)
            assertTrue(peer.logs.any{it.contains("inbound gated id=5703")})
            assertTrue(peer.logs.any{it.contains("INVALID_BOOLEAN")})
            handoff.acceptBootstrap(result)
        }
    }

    private fun beginDualHandoff(peer:Peer,handoffWaitMs:Long=30_000L):java.util.concurrent.Future<WifiBootstrap> {
        val accessory=SyntheticAccessory();peer.initialize()
        val work=peer.negotiate(handoffWaitMs)
        authenticateV2(peer,accessory,byteArrayOf(0x57,3,0x43,1),byteArrayOf(0x57,2,0x43,0))
        assertEquals(0x5702,peer.nextOf(0x5702).first)
        assertEquals(0x4300,peer.next().first)
        return work
    }
    @Test(timeout=10000) fun malformedStartPeerDeclarationDoesNotPoisonLaterValidHandoff(){
        Peer(2).use{peer->
            val work=beginDualHandoff(peer)
            peer.command(0x4301,startSession()+listOf(8 to byteArrayOf(2)))
            peer.command(0x4301,startSession()+listOf(5 to IapWire.cstring("peer-source"),
                6 to IapWire.cstring("peer-sdk"),8 to byteArrayOf(1)))
            peer.command(0x5703,wifiAnnouncement())
            val result=work.get(3,TimeUnit.SECONDS)
            assertEquals(StartSessionPeerInfo("peer-source","peer-sdk",true),result.startSession!!.startSessionPeerInfo)
            assertEquals(result.startSession!!.startSessionPeerInfo,result.endpoint!!.startSessionPeerInfo)
            assertNotNull(result.authentication)
            assertFalse(result.authentication!!.aaTrusted)
            assertTrue(result.authentication!!.challengeSignatureVerified)
            assertTrue(peer.logs.any{it.contains("INVALID_BOOLEAN")})
        }
    }
    @Test(timeout=10000) fun announcementBeforeDelayed4301UsesFullStartInsteadOfUnsupportedNetworkOnly() {
        Peer(2).use{peer->
            val work=beginDualHandoff(peer)
            peer.command(0x5703,wifiAnnouncement())
            assertTrue(peer.awaitingStart.await(2,TimeUnit.SECONDS))
            assertFalse("must still be waiting for the requested 4301",work.isDone)
            peer.command(0x4301,startSession())
            val result=work.get(3,TimeUnit.SECONDS)
            assertEquals("192.0.2.1",result.address)
            assertEquals(3,result.security) // Existing 4301 mapping, not guessed from the 5703 enum.
            assertTrue(result.startSessionReady)
        }
    }
    @Test(timeout=10000) fun alreadyQueued4301IsConsumedAfter5703() {
        Peer(2).use{peer->
            val parsed=java.util.concurrent.CountDownLatch(1)
            val release=java.util.concurrent.CountDownLatch(1)
            peer.onBootstrapLog={message->if(message.startsWith("5703 parsed security=")){
                parsed.countDown();assertTrue(release.await(3,TimeUnit.SECONDS))
            }}
            val work=beginDualHandoff(peer)
            try{
                peer.command(0x5703,wifiAnnouncement())
                assertTrue(parsed.await(2,TimeUnit.SECONDS))
                peer.command(0x4301,startSession())
                // Link ACK proves the reader has accepted the 4301 while the bootstrap consumer
                // is still finishing its 5703. It is queued, exactly as in the reported log.
                var frame=IapWire.read(peer.carIn)
                while(frame.ack!=peer.seq)frame=IapWire.read(peer.carIn)
                assertTrue(frame.payload.isEmpty())
            }finally{release.countDown()}
            assertEquals("192.0.2.1",work.get(3,TimeUnit.SECONDS).address)
        }
    }
    @Test(timeout=10000) fun missingRequested4301FallsBackToSupportedAnnouncementWithinBudget() {
        Peer(2).use{peer->
            val work=beginDualHandoff(peer,handoffWaitMs=1000)
            peer.command(0x5703,wifiAnnouncement(security=2))
            assertTrue(peer.awaitingStart.await(2,TimeUnit.SECONDS))
            peer.command(0x5703,wifiAnnouncement(security=2)) // Does not extend the original deadline.
            val result=work.get(3,TimeUnit.SECONDS)
            assertNull(result.endpoint)
            assertEquals(SecurityEntry.DISCOVERY,result.endpointSource)
            assertTrue(peer.logs.any{it.startsWith("Requested 4301 deadline reached")})
        }
    }
    @Test(timeout=10000) fun supportedAnnouncementSecurityAfter4301DeadlineIsPreserved() {
        Peer(2).use{peer->
            val work=beginDualHandoff(peer,handoffWaitMs=1000)
            peer.command(0x5703,wifiAnnouncement(security=3))
            val result=work.get(3,TimeUnit.SECONDS)
            assertEquals(3,result.security)
            assertNull(result.endpoint)
        }
    }
    @Test(timeout=10000) fun received4301StillChecksCredentialsAgainstAnnouncement() {
        Peer(2).use{peer->
            val work=beginDualHandoff(peer)
            peer.command(0x5703,wifiAnnouncement())
            assertTrue(peer.awaitingStart.await(2,TimeUnit.SECONDS))
            peer.command(0x4301,startSession(password="different-password"))
            val error=assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause!!
            assertTrue(error.message!!.contains("credentials conflict"))
            assertFalse(error.message!!.contains("different-password"))
        }
    }
    @Test(timeout=15000) fun runtimeReauthenticatesAndUsesItsOwnCapabilityList() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val accepted=java.util.concurrent.atomic.AtomicReference<io.github.iamr0s.carvex.sessioncore.AcceptedIdentification>()
            val work=peer.worker.submit<io.github.iamr0s.carvex.sessioncore.CapabilityRegistry> {
                Bootstrap.negotiateRuntime(peer.link,"02:11:22:33:44:55","synthetic",PairIdentity("synthetic",ByteArray(32)),
                    experimentalIntegrityOnly=true,onIdentificationReady={accepted.set(it)}){}
            }
            authenticateV2(peer,accessory,byteArrayOf(0xff.toByte(),0xfb.toByte()),byteArrayOf(0xff.toByte(),0xfa.toByte()),transport=24)
            // 运行时链路在认证后会无条件发 4E0C；读掉并 ACK，否则对端等不到 ACK 会超时。
            assertEquals(0x4e0c,peer.nextRaw().first)
            val result=work.get(3,TimeUnit.SECONDS)
            assertEquals(setOf(io.github.iamr0s.carvex.sessioncore.MessageId(0xff,0xfa)),result.receivedByAccessory)
            assertFalse(result.receivedByAccessory.any{it.value==0x5702})
            val session=requireNotNull(accepted.get())
            assertEquals(peer.link.generation,session.generation);assertEquals(peer.link.linkEpoch,session.epoch)
            assertEquals("synthetic-accessory",session.info.name)
            assertEquals(result,session.capabilities)
        }
    }

    /** These are well-shaped registered power fields; this test does not prove full feature validation. */
    @Test(timeout=15000) fun initialIdentificationUsesWellShapedRegisteredPowerFields() {
        Peer(2).use { peer ->
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            val fields=identification()
            assertArrayEquals(byteArrayOf(0),fields.first{it.first==8}.second)
            assertArrayEquals(byteArrayOf(0,100),fields.first{it.first==9}.second)
            peer.command(0x1d01,fields)
            assertEquals(0x1d02,peer.next().first)
            assertEquals(0xaa00,peer.next().first)
            work.cancel(true)
        }
    }

    /** 24A446's 1D06 callback only consumes 0..5, not initial message declarations. */
    @Test(timeout=15000) fun identificationUpdateAfterAcceptanceIsAppliedWithoutRestartingTheSession() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory()
            peer.initialize()
            val work=peer.negotiate()
            authenticateV2(peer,accessory,byteArrayOf(0x57,3),byteArrayOf(0x57,2))
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x1d06,listOf(0 to IapWire.cstring("renamed")))
            peer.command(0x5703,wifiAnnouncement(security=2))
            val result=work.get(3,TimeUnit.SECONDS)
            assertTrue("1d06 更新必须被应用",peer.logs.any{it.startsWith("INFO 1d06 update")})
            assertEquals("synthetic",result.ssid)
            val info=requireNotNull(result.identification).info
            assertEquals("renamed",info.name)
            assertEquals("synthetic-model",info.modelIdentifier)
            assertEquals("synthetic-maker",info.manufacturer)
            assertEquals("synthetic-serial",info.serialNumber)
            assertEquals("firmware-1",info.firmwareVersion)
            assertEquals("hardware-1",info.hardwareVersion)
            assertEquals(listOf(0x5703),info.accessorySends.map{it.value})
            assertEquals(listOf(0x5702),info.accessoryReceives.map{it.value})
            assertNoApplicationOutput(peer) // No second 1D02/AA00 or update acknowledgment.
        }
    }

    @Test(timeout=10000) fun missingInitialFieldsAreRejectedThenCorrectedOnTheSameLink() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val generation=peer.link.generation;val epoch=peer.link.linkEpoch
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification().filterNot{it.first==0||it.first==13})
            val rejected=peer.next()
            assertEquals(0x1d03,rejected.first)
            assertArrayEquals(byteArrayOf(0,4,0,0,0,4,0,13),IapWire.fields(rejected.second.ordered))
            assertFalse(work.isDone)
            peer.command(0x1d01,identification())
            // A second 1D00 or AA00 before acceptance would fail this exact sequence.
            assertEquals(0x1d02,peer.next().first)
            finishAuthenticationV2(peer,accessory)
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x5703,wifiAnnouncement(security=2))
            val result=work.get(3,TimeUnit.SECONDS)
            assertEquals("synthetic-accessory",requireNotNull(result.identification).info.name)
            assertEquals(generation,peer.link.generation);assertEquals(epoch,peer.link.linkEpoch)
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=10000) fun malformedInitialMessageListDoesNotPoisonCorrectedIdentity() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            val malformed=identification(byteArrayOf(0x57)).map{
                if(it.first==0)0 to IapWire.cstring("must-not-publish") else it
            }
            peer.command(0x1d01,malformed)
            val rejected=peer.next()
            assertEquals(0x1d03,rejected.first)
            assertArrayEquals(byteArrayOf(0,4,0,6),IapWire.fields(rejected.second.ordered))
            assertFalse(work.isDone)
            peer.command(0x1d01,identification())
            assertEquals(0x1d02,peer.next().first)
            finishAuthenticationV2(peer,accessory)
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x5703,wifiAnnouncement(security=2))
            val result=work.get(3,TimeUnit.SECONDS)
            assertEquals("synthetic-accessory",requireNotNull(result.identification).info.name)
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=10000) fun correctedIdentificationPreservesPreviouslyVerifiedAuthentication() {
        Peer(1).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate()
            assertEquals(0xaa00,peer.next().first)
            peer.command(0xaa01,listOf(0 to accessory.certificate))
            val challenge=peer.next();assertEquals(0xaa02,challenge.first)
            peer.command(0xaa03,listOf(0 to accessory.sign(requireNotNull(challenge.second[0]))))
            assertEquals(0xaa05,peer.next().first)
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification().filterNot{it.first==0})
            assertEquals(0x1d03,peer.next().first)
            peer.command(0x1d01,identification())
            assertEquals(0x1d02,peer.next().first)
            // Read exact application sequence: authentication must not restart after correction.
            assertEquals(0x5702,peer.next().first)
            peer.command(0x5703,wifiAnnouncement(security=2))
            assertTrue(requireNotNull(work.get(3,TimeUnit.SECONDS).authentication).challengeSignatureVerified)
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=10000) fun acceptanceSendFailureDoesNotProduceRejectionOrStartAuthentication() {
        Peer(2).use { peer ->
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            peer.failMessage=0x1d02
            peer.command(0x1d01,identification())
            val error=assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause
            assertTrue(error is java.io.IOException)
            assertEquals(listOf(0x1d00,0x1d02),peer.outputAttempts.toList())
            assertFalse(peer.logs.any{it.startsWith("INFO Identify")})
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=10000) fun rejectionSendFailureDoesNotEnterCorrectionWaitOrAcceptAnotherMessage() {
        Peer(2).use { peer ->
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            peer.failMessage=0x1d03
            peer.command(0x1d01,identification().filterNot{it.first==0})
            val error=assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause
            assertTrue(error is java.io.IOException)
            assertEquals(listOf(0x1d00,0x1d03),peer.outputAttempts.toList())
            assertFalse(peer.logs.any{it.startsWith("1d03 sent; awaiting corrected")})
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=10000) fun linkRestartBeforeRejectionSendCannotWriteIntoTheNextEpoch() {
        Peer(2).use { peer ->
            peer.initialize()
            val epoch=peer.link.linkEpoch
            val invalidated=java.util.concurrent.CountDownLatch(1)
            val binding=peer.link.bindEpoch(epoch){invalidated.countDown()}
            try{
                peer.onBootstrapLog={message->
                    if(message.contains("0x1d03")&&message.contains("queued")){
                        peer.carOut.write(IapWire.detection);peer.carOut.flush()
                        assertTrue("Detection must invalidate the old transaction",invalidated.await(2,TimeUnit.SECONDS))
                    }
                }
                val work=peer.negotiate()
                assertEquals(0x1d00,peer.next().first)
                peer.command(0x1d01,identification().filterNot{it.first==0})
                assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}
                assertTrue(peer.link.linkEpoch!=epoch)
                assertEquals(listOf(0x1d00),peer.outputAttempts.toList())
                assertFalse(peer.logs.any{it.startsWith("1d03 sent; awaiting corrected")})
            }finally{binding.close()}
        }
    }

    /** The retained two-second budget is local policy, not an inferred Apple timer. */
    @Test(timeout=10000) fun repeatedRejectionDoesNotRenewTheInitialDeadline() {
        Peer(2).use { peer ->
            peer.initialize()
            val work=peer.negotiate(identificationWaitMs=2_000L)
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification().filterNot{it.first==0})
            assertEquals(0x1d03,peer.next().first)
            Thread.sleep(1_200)
            peer.command(0x1d01,identification().filterNot{it.first==13})
            assertEquals(0x1d03,peer.next().first)
            val error=assertThrows(ExecutionException::class.java){work.get(1_300,TimeUnit.MILLISECONDS)}.cause
            assertTrue("original identification deadline must expire",error is IapStartupTimeout)
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=10000) fun cancellationWhileWaitingTerminatesWithoutARejectionPacket() {
        Peer(2).use { peer ->
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d05)
            val error=assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause
            assertTrue(error is java.io.IOException)
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=10000) fun cancellationAfterLocalRejectionTerminatesWithoutAnotherRejection() {
        Peer(2).use { peer ->
            peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification().filterNot{it.first==0})
            assertEquals(0x1d03,peer.next().first)
            peer.command(0x1d05)
            assertTrue(assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause is java.io.IOException)
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=10000) fun lateCancellationAndInitialMessageCannotReplaceAcceptedIdentity() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate()
            authenticateV2(peer,accessory,byteArrayOf(0x57,3),byteArrayOf(0x57,2))
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x1d05)
            peer.command(0x1d01,identification(byteArrayOf(0x43,1),byteArrayOf(0x43,0)).map{
                if(it.first==0)0 to IapWire.cstring("late-identity") else it
            })
            peer.command(0x5703,wifiAnnouncement(security=2))
            val info=requireNotNull(work.get(3,TimeUnit.SECONDS).identification).info
            assertEquals("synthetic-accessory",info.name)
            assertEquals(listOf(0x5703),info.accessorySends.map{it.value})
            assertEquals(listOf(0x5702),info.accessoryReceives.map{it.value})
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=10000) fun updateBeforeAcceptanceIsIgnoredButUpdateDuringAuthenticationIsApplied() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d06,listOf(1 to IapWire.cstring("too-early-model")))
            peer.command(0x1d01,identification())
            assertEquals(0x1d02,peer.next().first)
            // Identification is accepted; AA is still pending. These are independent states.
            peer.command(0x1d06,listOf(0 to IapWire.cstring("during-authentication")))
            peer.command(0x1d05) // A late cancel cannot cancel the accepted identification.
            finishAuthenticationV2(peer,accessory)
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x5703,wifiAnnouncement(security=2))
            val info=requireNotNull(work.get(3,TimeUnit.SECONDS).identification).info
            assertEquals("during-authentication",info.name)
            assertEquals("synthetic-model",info.modelIdentifier)
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=10000) fun malformedUpdateIsAtomicAndDoesNotRewriteDeclarations() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate()
            authenticateV2(peer,accessory,byteArrayOf(0x57,3),byteArrayOf(0x57,2))
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x1d06,listOf(0 to IapWire.cstring("must-not-commit"),1 to byteArrayOf(65,0,66)))
            // 6/7 are ignored in 1D06 even if their bytes would be invalid initial lists.
            peer.command(0x1d06,listOf(4 to IapWire.cstring("firmware-2"),6 to byteArrayOf(0x43),7 to byteArrayOf()))
            peer.command(0x5703,wifiAnnouncement(security=2))
            val info=requireNotNull(work.get(3,TimeUnit.SECONDS).identification).info
            assertEquals("synthetic-accessory",info.name)
            assertEquals("synthetic-model",info.modelIdentifier)
            assertEquals("firmware-2",info.firmwareVersion)
            assertEquals(listOf(0x5703),info.accessorySends.map{it.value})
            assertEquals(listOf(0x5702),info.accessoryReceives.map{it.value})
            assertNoApplicationOutput(peer)
        }
    }

    /** Each malformed candidate is an independent transaction on the same link.
     *  No fixture silently repairs omitted fields; rejection order and repeats stay observable. */
    private fun rejectInitialCandidatesThenRecover(
        candidates:List<Pair<List<Pair<Int,ByteArray>>,List<Int>>>,
    ) = rejectInitialCandidatesWithPayloadThenRecover(candidates.map{(fields,ids)->
        fields to ids.map{io.github.iamr0s.carvex.sessioncore.RawParameter(it,byteArrayOf())}})

    private fun rejectInitialCandidatesWithPayloadThenRecover(
        candidates:List<Pair<List<Pair<Int,ByteArray>>,List<io.github.iamr0s.carvex.sessioncore.RawParameter>>>,
    ) {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val generation=peer.link.generation;val epoch=peer.link.linkEpoch
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            for((fields,rejectedParameters) in candidates){
                peer.command(0x1d01,fields)
                val rejected=peer.next()
                assertEquals(0x1d03,rejected.first)
                val expected=IapWire.fields(rejectedParameters.map{it.id to it.value})
                assertArrayEquals(expected,IapWire.fields(rejected.second.ordered))
                assertFalse("a rejected candidate must leave this link available for correction",work.isDone)
                assertFalse(peer.outputAttempts.contains(0x1d02))
                assertFalse(peer.outputAttempts.contains(0xaa00))
                assertFalse(peer.outputAttempts.contains(0x5702))
                assertFalse(peer.outputAttempts.contains(0x4300))
            }
            peer.command(0x1d01,identification())
            assertEquals(0x1d02,peer.next().first)
            finishAuthenticationV2(peer,accessory)
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x5703,wifiAnnouncement(security=2))
            val info=requireNotNull(work.get(3,TimeUnit.SECONDS).identification).info
            assertEquals("synthetic-accessory",info.name)
            assertEquals("en",info.currentLanguage)
            assertEquals(listOf("en"),info.supportedLanguages)
            assertNull(info.ppid)
            assertEquals(listOf(0x5703),info.accessorySends.map{it.value})
            assertEquals(listOf(0x5702),info.accessoryReceives.map{it.value})
            assertEquals(generation,peer.link.generation);assertEquals(epoch,peer.link.linkEpoch)
            assertEquals(1,peer.outputAttempts.count{it==0x1d00})
            assertEquals(1,peer.outputAttempts.count{it==0x1d02})
            assertEquals(1,peer.outputAttempts.count{it==0xaa00})
            assertEquals(candidates.size,peer.outputAttempts.count{it==0x1d03})
            assertFalse(peer.logs.any{it.contains("private-invalid-identity")})
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=15000) fun orderedInitialFieldsReplaceListsAndScalarsWhileLanguagesAccumulate() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            val fields=identification(byteArrayOf(0x43,1),byteArrayOf(0x43,0))+listOf(
                0 to IapWire.cstring("last-name"),12 to IapWire.cstring("zh"),
                13 to IapWire.cstring("zh"),34 to IapWire.cstring("first-ppid"),
                6 to byteArrayOf(0x57,3,0x57,3),7 to byteArrayOf(0x57,2,0x57,2),
                34 to IapWire.cstring("last-ppid"))
            peer.command(0x1d01,fields)
            assertEquals(0x1d02,peer.next().first)
            finishAuthenticationV2(peer,accessory)
            assertEquals(0x5702,peer.next().first)
            // 1D06 is a different consumer: these initial-only fields must not
            // overwrite the accepted language/PPID, even with malformed values.
            peer.command(0x1d06,listOf(12 to byteArrayOf(65),13 to byteArrayOf(),
                34 to IapWire.cstring("update-must-not-replace-ppid")))
            peer.command(0x5703,wifiAnnouncement(security=2))
            val info=requireNotNull(work.get(3,TimeUnit.SECONDS).identification).info
            assertEquals("last-name",info.name)
            assertEquals("zh",info.currentLanguage)
            assertEquals(listOf("en","zh"),info.supportedLanguages)
            assertEquals("last-ppid",info.ppid)
            assertEquals(listOf(0x5703),info.accessorySends.map{it.value})
            assertEquals(listOf(0x5702),info.accessoryReceives.map{it.value})
            assertEquals(fields.map{it.first},info.rawParameters.map{it.id})
            // If repeated lists were unioned, 4300 would have been sent as well.
            assertFalse(peer.outputAttempts.contains(0x4300))
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=15000) fun emptyInitialStringsAndEmbeddedNulWithFinalNulRemainValid() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate()
            assertEquals(0x1d00,peer.next().first)
            val fields=identification().map{(id,value)->when(id){
                0,12,13->id to byteArrayOf(0)
                1->id to byteArrayOf(65,0,66,0)
                else->id to value
            }}+listOf(34 to byteArrayOf(0))
            peer.command(0x1d01,fields)
            assertEquals(0x1d02,peer.next().first)
            finishAuthenticationV2(peer,accessory)
            assertEquals(0x5702,peer.nextOf(0x5702).first)
            peer.command(0x5703,wifiAnnouncement(security=2))
            val info=requireNotNull(work.get(3,TimeUnit.SECONDS).identification).info
            assertEquals("",info.name);assertEquals("A",info.modelIdentifier)
            assertEquals("",info.currentLanguage);assertEquals(listOf(""),info.supportedLanguages)
            assertEquals("",info.ppid)
            assertNoApplicationOutput(peer)
        }
    }

    @Test(timeout=15000) fun malformedInitialStringsAreRejectedWithoutLaterValidValuesMaskingThem() {
        val candidates=listOf(0,12,13,34).map{id->
            // Missing final NUL, including an earlier NUL, must not be accepted as a CString.
            val bad="private-invalid-identity".toByteArray()+byteArrayOf(0,65)
            val fields=identification().filterNot{it.first==id}+
                listOf(id to bad,id to IapWire.cstring("later-valid"))
            fields to if(id==13)listOf(13,13)else listOf(id)
        }
        rejectInitialCandidatesThenRecover(candidates)
    }

    @Test(timeout=15000) fun laterMalformedInitialScalarsAndLanguagesRejectEarlierValidValues() {
        val candidates=listOf(0,12,13,34).map{id->
            val initial=identification()+if(id==34)listOf(34 to IapWire.cstring("first"))else emptyList()
            (initial+listOf(id to byteArrayOf())) to if(id==13)listOf(13,13)else listOf(id)
        }
        rejectInitialCandidatesThenRecover(candidates)
    }

    @Test(timeout=15000) fun repeatedEqualSupportedLanguageProducesOneRejectionAndCanBeCorrected() {
        rejectInitialCandidatesThenRecover(listOf(
            (identification()+listOf(13 to IapWire.cstring("en"))) to listOf(13)))
    }

    @Test(timeout=15000) fun trulyUnknownInitialFieldsRejectAtBeginningMiddleAndEnd() {
        val fields=identification()
        val candidates=listOf(0,fields.size/2,fields.size).map{position->
            (fields.take(position)+listOf(77 to byteArrayOf())+fields.drop(position)) to listOf(77)
        }
        rejectInitialCandidatesThenRecover(candidates)
    }

    @Test(timeout=15000) fun registeredReservedInitialFieldStillRejects() {
        rejectInitialCandidatesThenRecover(listOf(
            (identification()+listOf(19 to byteArrayOf())) to listOf(19)))
    }

    @Test(timeout=15000) fun firstParseFailurePrecedesMissingRequiredCoreFieldsAndLaterFailures() {
        val fields=identification().filterNot{it.first==0||it.first==13}
        rejectInitialCandidatesThenRecover(listOf(
            (listOf(12 to byteArrayOf(65))+fields+listOf(34 to byteArrayOf())) to listOf(12),
            (listOf(34 to byteArrayOf())+fields) to listOf(34),
            (listOf(77 to byteArrayOf())+fields) to listOf(77)))
    }

    @Test(timeout=15000) fun repeatedInitialMessageListsCannotHideOddLengthOccurrences() {
        val candidates=listOf(6,7).flatMap{id->
            val valid=identification().first{it.first==id}.second
            listOf(
                (identification()+listOf(id to byteArrayOf(0x57),id to valid)) to listOf(id),
                (identification()+listOf(id to valid,id to byteArrayOf(0x57))) to listOf(id))
        }
        rejectInitialCandidatesThenRecover(candidates)
    }

    @Test(timeout=15000) fun emptyReplacementMessageListReachesTheMissingPairValidator() {
        // Empty is syntactically valid and replaces 5703. Remaining 5702 now makes
        // this group incomplete: native reason2 flags field6 without ID bytes.
        rejectInitialCandidatesThenRecover(listOf(
            (identification()+listOf(6 to byteArrayOf())) to listOf(6)))
    }

    @Test(timeout=15000) fun missingOrMalformedBluetoothComponentRejectsThenRecoversOnSameLink() {
        rejectInitialCandidatesThenRecover(listOf(
            identification().filterNot{it.first==0||it.first==17} to listOf(0,17),
            identification().filterNot{it.first==17} to listOf(17),
            identification(transport=24) to listOf(17),
            (identification().filterNot{it.first==17}+listOf(17 to byteArrayOf())) to listOf(17),
            (identification()+listOf(24 to IapWire.fields(listOf(0 to IapWire.be16(0),
                1 to IapWire.cstring("duplicate-id"),4 to byteArrayOf())))) to listOf(24)))
    }

    @Test(timeout=15000) fun everyHalfMessageGroupRejectsTheMissingDirectionBeforeAcceptance() {
        val candidates=listOf(0x5700 to 0x5701,0x5703 to 0x5702,0x4301 to 0x4300).flatMap{(sent,received)->
            listOf(identification(IapWire.be16(sent),byteArrayOf()) to listOf(7),
                identification(byteArrayOf(),IapWire.be16(received)) to listOf(6))}
        rejectInitialCandidatesThenRecover(candidates)
    }

    @Test(timeout=15000) fun reversedGroupsRejectTheirActualIdsNotInventedReasons() {
        rejectInitialCandidatesWithPayloadThenRecover(listOf(0x5700 to 0x5701,0x5703 to 0x5702,0x4301 to 0x4300).map{(sent,received)->
            identification(IapWire.be16(received),IapWire.be16(sent)) to listOf(
                io.github.iamr0s.carvex.sessioncore.RawParameter(6,IapWire.be16(received)),
                io.github.iamr0s.carvex.sessioncore.RawParameter(7,IapWire.be16(sent)))})
    }

    @Test(timeout=15000) fun firstWifiFailureProducesSkippedGroupPayloadAndStillChecksCarPlay() {
        rejectInitialCandidatesWithPayloadThenRecover(listOf(
            identification(byteArrayOf(0x57,0,0x57,3),byteArrayOf(0x57,2,0x43,0)) to listOf(
                io.github.iamr0s.carvex.sessioncore.RawParameter(6,byteArrayOf(0x57,3)),
                io.github.iamr0s.carvex.sessioncore.RawParameter(7,byteArrayOf(0x57,2)))))
    }

    @Test(timeout=10000) fun messageCorrectionAfterAuthenticationDoesNotRepeatAaOrPublishEarlyHandoff() {
        Peer(1).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val generation=peer.link.generation;val epoch=peer.link.linkEpoch
            val work=peer.negotiate()
            finishAuthenticationV2(peer,accessory) // Same AA exchange; v1 performs it BEFORE 1D00.
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification(byteArrayOf(0x57,3),byteArrayOf()))
            val rejected=peer.next();assertEquals(0x1d03,rejected.first)
            assertArrayEquals(byteArrayOf(0,4,0,7),IapWire.fields(rejected.second.ordered))
            peer.command(0x5703,wifiAnnouncement(security=2)) // Rejected capabilities must not authorize this.
            peer.command(0x1d01,identification())
            assertEquals(0x1d02,peer.next().first)
            assertEquals(0x5702,peer.next().first)
            assertFalse(work.isDone)
            peer.command(0x5703,wifiAnnouncement(security=2))
            val result=work.get(3,TimeUnit.SECONDS)
            assertTrue(requireNotNull(result.authentication).challengeSignatureVerified)
            assertEquals(generation,peer.link.generation);assertEquals(epoch,peer.link.linkEpoch)
            assertEquals(1,peer.outputAttempts.count{it==0xaa00})
            assertEquals(1,peer.outputAttempts.count{it==0x1d00})
            assertEquals(1,peer.outputAttempts.count{it==0x5702})
            assertTrue(peer.logs.any{it.contains("inbound gated id=5703")})
        }
    }

    @Test(timeout=10000) fun validIdentificationWithoutHandoffIsAcceptedButCannotReportNetworkSuccess() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.negotiate(handoffWaitMs=500)
            assertEquals(0x1d00,peer.next().first)
            // Both transports, and explicit CarPlay flag, but NO network message group.
            peer.command(0x1d01,identification(byteArrayOf(),byteArrayOf())+listOf(24 to
                IapWire.fields(listOf(0 to IapWire.be16(1),1 to IapWire.cstring("wireless"),4 to byteArrayOf()))))
            assertEquals(0x1d02,peer.next().first)
            finishAuthenticationV2(peer,accessory)
            assertEquals(0x4e0c,peer.nextRaw().first)
            peer.command(0x5703,wifiAnnouncement(security=2))
            val error=assertThrows(ExecutionException::class.java){work.get(3,TimeUnit.SECONDS)}.cause
            assertTrue(error is io.github.iamr0s.carvex.sessioncore.TransportException)
            assertEquals(io.github.iamr0s.carvex.sessioncore.TransportErrorCategory.PLATFORM_UNSUPPORTED,
                (error as io.github.iamr0s.carvex.sessioncore.TransportException).category)
            assertEquals(0,peer.outputAttempts.count{it==0x1d03||it==0x4300||it==0x5702})
            assertTrue(peer.logs.any{it.contains("no locally supported network handoff route")})
        }
    }

    @Test(timeout=10000) fun airPlayRuntimeRequires24NotTheBluetoothComponentAndAllowsCorrection() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory();peer.initialize()
            val work=peer.worker.submit<io.github.iamr0s.carvex.sessioncore.AcceptedIdentification>{
                Bootstrap.negotiateRuntimeIdentification(peer.link,"02:11:22:33:44:55","synthetic",
                    PairIdentity("synthetic",ByteArray(32)),experimentalIntegrityOnly=true,log={peer.logs+=it})}
            assertEquals(0x1d00,peer.next().first)
            peer.command(0x1d01,identification(byteArrayOf(),byteArrayOf(),transport=17))
            val rejected=peer.next();assertEquals(0x1d03,rejected.first)
            assertArrayEquals(byteArrayOf(0,4,0,24),IapWire.fields(rejected.second.ordered))
            peer.command(0x1d01,identification(byteArrayOf(),byteArrayOf(),transport=24))
            assertEquals(0x1d02,peer.next().first)
            finishAuthenticationV2(peer,accessory)
            assertEquals(0x4e0c,peer.nextRaw().first)
            val accepted=work.get(3,TimeUnit.SECONDS)
            assertTrue(accepted.capabilities.componentCapabilities.wirelessCarPlayAdvertised)
            assertFalse(accepted.capabilities.networkHandoff.hasSupportedRoute)
            assertEquals(setOf(io.github.iamr0s.carvex.sessioncore.LinkTransport.WIFI_TCP),accepted.capabilities.transportComponents)
            assertEquals(0,peer.outputAttempts.count{it==0x4300||it==0x5702})
        }
    }

    /** 4E0E 参数 0 是蓝牙 MAC，参数 1 是设备唯一标识（C-0024 的 copyUniqueDeviceID 一解）。 */
    @Test(timeout=15000) fun transportIdentifierCarriesTheDeviceIdentifierAsSecondParameter() {
        Peer(2).use { peer ->
            val accessory=SyntheticAccessory()
            peer.initialize()
            peer.negotiate()
            authenticateV2(peer,accessory,byteArrayOf(0x43,1),byteArrayOf(0x4e,0x0e,0x43,0))
            val frame=peer.nextOf(0x4e0e)
            assertEquals(listOf(0,1),frame.second.ordered.map{it.first})
            assertEquals("02:11:22:33:44:55",IapWire.text(requireNotNull(frame.second[0])))
            assertEquals("synthetic",IapWire.text(requireNotNull(frame.second[1])))
        }
    }
}
