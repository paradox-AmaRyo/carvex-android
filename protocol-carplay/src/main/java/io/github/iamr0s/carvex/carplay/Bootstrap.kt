package io.github.iamr0s.carvex.carplay
import io.github.iamr0s.carvex.sessioncore.*

import android.annotation.SuppressLint
import android.bluetooth.*
import android.content.Context
import android.net.*
import android.net.wifi.WifiNetworkSpecifier
import android.os.Build
import io.github.iamr0s.carvex.carplay.core.*
import kotlinx.coroutines.*
import java.net.*
import java.nio.ByteBuffer
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class BootstrapAuthentication(val generation:Int,val epoch:Long,val controlVersion:Int,val aaTrusted:Boolean,
    val challengeSignatureVerified:Boolean=false) {
    fun accepted(experimentalIntegrityOnly:Boolean)=aaTrusted||(experimentalIntegrityOnly&&challengeSignatureVerified)
}

data class BootstrapEndpoint(val address:String,val port:Int,val receiver:String,val publicKey:ByteArray?,val addresses:List<String> = listOf(address),val metadata:ReceiverMetadata?=null,val source:SecurityEntry=SecurityEntry.IAP_START,
    /** Original 4301 declarations stay bound to this endpoint, separate from discovery. */
    val startSessionPeerInfo:StartSessionPeerInfo?=null)

/** Credentials and endpoint discovery are separate; a 57/03 response need not contain 43/01. */
data class WifiBootstrap(val ssid:String,val password:String,val security:Int,
    val endpoint:BootstrapEndpoint?,val receiverCanReceive:Set<Int> =emptySet(),
    val bootstrapTransport:SecurityTransport=SecurityTransport.BLUETOOTH_WIFI,
    val authentication:BootstrapAuthentication?=null,
    /** Accepted 43/01 snapshot survives selecting a different discovered endpoint. */
    val startSession:BootstrapEndpoint?=endpoint?.takeIf{it.source==SecurityEntry.IAP_START},
    /** Current-link identity updates; never inherited as authentication by a new link. */
    val identification:AcceptedIdentification?=null) {
    constructor(ssid:String,password:String,security:Int,address:String,port:Int,receiver:String,publicKey:ByteArray?,
                receiverCanReceive:Set<Int> =emptySet()):this(ssid,password,security,
        BootstrapEndpoint(address,port,receiver,publicKey),receiverCanReceive)
    val address:String get()=requireNotNull(endpoint).address
    val port:Int get()=requireNotNull(endpoint).port
    val receiver:String get()=requireNotNull(endpoint).receiver
    val publicKey:ByteArray? get()=endpoint?.publicKey
    fun sameNetworkAs(other:WifiBootstrap):Boolean {
        if(ssid!=other.ssid||password!=other.password||security!=other.security)return false
        val left=endpoint;val right=other.endpoint
        if(left==null||right==null)return left==right
        return left.address==right.address&&left.port==right.port&&left.receiver==right.receiver&&
            left.addresses==right.addresses&&((left.publicKey==null&&right.publicKey==null)||
                (left.publicKey!=null&&right.publicKey!=null&&left.publicKey.contentEquals(right.publicKey)))
    }
    fun resolved(address:String,port:Int,receiver:String,publicKey:ByteArray?,metadata:ReceiverMetadata?=null):WifiBootstrap {
        require(port in 1..65535&&receiver.isNotBlank())
        return copy(endpoint=BootstrapEndpoint(address,port,receiver,publicKey,metadata=metadata,source=SecurityEntry.DISCOVERY))
    }
    val endpointSource:SecurityEntry get()=endpoint?.source?:SecurityEntry.DISCOVERY
    val startSessionReady:Boolean get()=startSession!=null
    override fun toString()="WifiBootstrap(endpointPresent="+(endpoint!=null)+")"
    companion object {
        /** WIFI_CONFIG_PSK_V1 has evidence for value 2 only; no guessed open/enterprise fallback. */
        fun networkOnly(announcement:WifiAnnouncement,received:Set<Int>):WifiBootstrap {
            announcement.requireNetworkOnly()
            val security=requireNotNull(announcement.security)
            val password=announcement.password?:if(security==0)"" else
                throw WifiConfigurationException(2,WifiConfigurationProblem.MISSING_FIELD)
            return WifiBootstrap(requireNotNull(announcement.ssid),password,security,null,received.toSet())
        }
    }
}

data class NetworkPath(val network:Network,val properties:LinkProperties)

/** Host-side digital-car-key matcher. A null result means the platform has no
 * result (the firmware emits no 4303); an empty list is a valid matched set and
 * emits a parameterless 4303. The matcher never receives raw bytes. */
typealias DigitalKeyMatcher = (List<String>) -> List<String>?
/** Platform handoff observation for 4301. The callback receives the original
 * fields only after all known syntax has passed. It must not assume that a
 * non-empty request satisfies Android's endpoint or network requirements. */
typealias CarPlayStartRequest = (IapFields) -> Unit
/** Platform handoff observation for 5703. null represents the firmware's
 * valid empty-body dispatch and is deliberately not converted to credentials. */
typealias WifiAnnouncementHandler = (WifiAnnouncement?) -> Unit

/** Result of the host Wi-Fi sharing provider for one 5700 request. [status]
 * is the source 16-bit value; the wire response carries its low byte and only
 * status==0 permits the optional credential fields. */
data class DeviceWifiInfo(val status:Int,val security:Int?=null,val ssid:String?=null,val passphrase:String?=null) {
    init {
        require(status in 0..0xffff)
        require(security==null||security in 0..255)
    }
}
typealias DeviceWifiInfoProvider = () -> DeviceWifiInfo?

/** Missing Wi-Fi configuration proves no USB readiness. A wired result requires platform evidence. */
fun classifyCarPlayPath(config:WifiBootstrap?,usbTransportReady:Boolean=false):CarPlayBootstrapPath? =
    config?.let(CarPlayBootstrapPath::Wireless) ?: if(usbTransportReady)CarPlayBootstrapPath.Wired else null

class IapStartupTimeout(message:String,val canFallback:Boolean):SocketTimeoutException(message)

object Bootstrap {
    internal fun declarationPairComplete(request:Int,response:Int,accessoryReceives:Set<Int>,accessorySends:Set<Int>)=
        request in accessoryReceives&&response in accessorySends
    /** Capability ids as the peer reported them: a refusal has to name what was actually advertised,
     *  otherwise the next failure reads the same as a peer that advertised nothing at all. */
    private fun ids16(values:Collection<Int>)=values.sorted().joinToString(prefix="[",postfix="]"){
        java.lang.String.format(java.util.Locale.ROOT,"0x%04X",it)
    }
    /** Whole-handshake budget. The caller's stage deadline is the outer bound; this is the fallback that
     *  turns a silent accessory into a reported timeout instead of a hung attempt. */
    private const val HANDSHAKE_DEADLINE_MS=90_000L
    /** After the Wi-Fi configuration arrives, how long a still-missing 0x5703 announcement is awaited. */
    private const val ANNOUNCEMENT_WAIT_MS=30_000L
    /** A fresh SYN invalidates all Identification/AA state. Re-run the bootstrap a small number of
     * times on the new link generation instead of continuing with stale credentials. */
    private const val MAX_BOOTSTRAP_LINK_RESTARTS=2
    private class BootstrapLinkRestart(cause:Throwable?=null):IllegalStateException(
        "iAP link changed during bootstrap",cause)
    @SuppressLint("MissingPermission")
    fun devices(context:Context):List<Device> {
        val adapter=context.getSystemService(BluetoothManager::class.java).adapter?:return emptyList()
        return adapter.bondedDevices.map{Device(it.name?:"未命名设备",it.address)}.sortedBy{it.name}
    }
    @SuppressLint("MissingPermission")
    suspend fun bluetooth(context:Context,o:Options,r:Resources,log:(String)->Unit):BluetoothSocket {
        val adapter=context.getSystemService(BluetoothManager::class.java).adapter?:error("Bluetooth unavailable")
        check(adapter.isEnabled){"请先开启蓝牙"}
        require(BluetoothAdapter.checkBluetoothAddress(o.target)){"请选择已配对车机"}
        val device=adapter.bondedDevices.singleOrNull{it.address==o.target}?:error("目标车机尚未配对")
        fun trace(direction:String,transaction:String,outcome:String,detail:String?=null)=
            log(ProtocolTrace.event("BLUETOOTH","RFCOMM",direction,transaction,outcome,detail))
        val bonded=device.bondState==BluetoothDevice.BOND_BONDED
        val servicePlan=WiapBluetoothPolicy.plan(device.uuids?.map{it.uuid},o.listen)
        log("Bluetooth target paired="+bonded+" uuidSource=platform_cache observation="+servicePlan.observation+
            " uuidCount="+servicePlan.cachedUuidCount+" freshness=unverified fullSdp=unavailable")
        return coroutineScope {
            // 只注册普通手机 WiAP 角色；Sink 是固件的替代角色，不是额外兼容监听。
            // 公共 SDK 的两个 listener 仍是独立 channel，也不能自定义 SDP profile 属性。
            log("RFCOMM localRole=PHONE_WIAP sdpTopology=independent_channels "+
                "customProfileDescriptor=unavailable preAcceptAdmission=unavailable")
            val listeners=WiapBluetoothPolicy.openPhoneListeners{service->
                try{
                    r.own(adapter.listenUsingRfcommWithServiceRecord(service.serviceName,service.localUuid))
                }catch(t:java.io.IOException){
                    if(o.listen&&service==WiapBluetoothPolicy.Service.LEGACY)throw t
                    log("Inbound RFCOMM "+service.inboundLabel+" registration unavailable: "+(t.message?:""));null
                }
            }.map{it.service.inboundLabel to it.socket}
            val outboundCandidates=servicePlan.outbound
            // UUID 列表没有 attribute4/channel 结果，不能套用苹果的精确 fallback 条件。
            // 候选只串行探测一次；保持既有超时与选中 socket 机制，方向仲裁另批处理。
            log("RFCOMM outbound policy=sdk_uuid_hint_probe listenOnly="+o.listen+
                " candidates="+outboundCandidates.map{it.service.outboundLabel+":"+it.basis})
            val winner=CompletableDeferred<BluetoothSocket>()
            val winnerSocket=java.util.concurrent.atomic.AtomicReference<BluetoothSocket?>(null)
            val activeOutbound=java.util.concurrent.atomic.AtomicReference<BluetoothSocket?>(null)
            val stopping=java.util.concurrent.atomic.AtomicBoolean(false)
            val remaining=java.util.concurrent.atomic.AtomicInteger(
                listeners.size+(if(outboundCandidates.isNotEmpty())1 else 0))
            val errors=java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
            fun failed(direction:String,t:Exception){
                if(stopping.get()||winner.isCompleted)return
                errors.add(t);log("${"RFCOMM "}${direction}${" failed before iAP: "}"+t.javaClass.simpleName+" "+(t.message?:""))
                trace(direction,"RFCOMM","failed",t.javaClass.simpleName)
                if(remaining.decrementAndGet()==0){
                    val error=java.io.IOException("Neither RFCOMM direction established a selected-peer connection")
                    errors.forEach{error.addSuppressed(it)};winner.completeExceptionally(error)
                }
            }
            fun select(socket:BluetoothSocket,direction:String){
                activeOutbound.compareAndSet(socket,null)
                if(stopping.get()||!winnerSocket.compareAndSet(null,socket)){
                    // 另一条方向也连上了（以前只 release、不记录）：这决定了"双方各持一条连接"这种
                    // 可能是否存在，而它正是 iAP 同步帧序错配的可疑成因之一。
                    log("RFCOMM other direction also connected; releasing it, initiator="+direction)
                    r.release(socket);return
                }
                if(!winner.complete(socket)){
                    winnerSocket.compareAndSet(socket,null);r.release(socket);return
                }
                log("${"RFCOMM selected initiator="}${direction}${"; peer matched; only this socket enters iAP"}")
                trace(direction,"RFCOMM","selected","peer_matched")
            }
            val workers=mutableListOf<Job>()
            try{
                if(listeners.isNotEmpty()){
                    log("RFCOMM local listener API calls succeeded="+listeners.map{it.first}+
                        "; SDP publication unverified; selected-peer wait deadline=60s")
                    listeners.forEach{(direction,server)->
                        workers+=launch(Dispatchers.IO){
                            val until=android.os.SystemClock.elapsedRealtime()+60_000
                            try{
                                while(isActive&&!stopping.get()&&!winner.isCompleted){
                                    val left=until-android.os.SystemClock.elapsedRealtime()
                                    if(left<=0)throw java.net.SocketTimeoutException("Selected peer RFCOMM listen deadline ("+direction+")")
                                    val socket=server.accept(left.toInt())
                                    if(socket.remoteDevice.address!=o.target){
                                        runCatching{socket.close()};log("Rejected unsolicited Bluetooth peer on "+direction);continue
                                    }
                                    r.own(socket)
                                    if(!isActive){r.release(socket);return@launch}
                                    select(socket,direction);return@launch
                                }
                            }catch(t:Exception){if(isActive)failed("inbound-"+direction,t)}
                        }
                    }
                }
                if(outboundCandidates.isNotEmpty()){
                    log("RFCOMM outbound attempt order="+outboundCandidates.map{it.service.outboundLabel}+
                        "; simultaneous listener="+listeners.isNotEmpty())
                    workers+=launch(Dispatchers.IO){
                        var last:Exception?=null
                        for(candidate in outboundCandidates){
                            if(!isActive||stopping.get()||winner.isCompleted)return@launch
                            val direction=candidate.service.outboundLabel
                            val uuid=candidate.service.remoteUuid
                            val socket=try{
                                device.createRfcommSocketToServiceRecord(uuid)
                            }catch(t:java.io.IOException){
                                last=t
                                log("RFCOMM $direction socket allocation failed: "+(t.message?:""))
                                continue
                            }
                            r.own(socket);activeOutbound.set(socket)
                            log("RFCOMM outbound $direction connect deadline=20s basis="+candidate.basis+
                                " policy=sdk_uuid_hint_probe")
                            trace("tx",direction,"attempt",candidate.basis.name)
                            val deadlineJob=launch{delay(20_000);if(winnerSocket.get()!==socket)runCatching{socket.close()}}
                            try{
                                socket.connect()
                                deadlineJob.cancel()
                                if(!isActive||stopping.get()){r.release(socket);return@launch}
                                select(socket,direction);return@launch
                            }catch(t:Exception){
                                last=t
                                deadlineJob.cancel()
                                activeOutbound.compareAndSet(socket,null)
                                if(winnerSocket.get()!==socket)r.release(socket)
                                if(t is CancellationException||t is SecurityException)throw t
                                if(isActive&&!stopping.get())log("RFCOMM $direction failed before iAP: "+t.javaClass.simpleName+
                                    " "+(t.message?:"")+"; SDP record absence not established")
                            }
                        }
                        activeOutbound.set(null)
                        if(isActive&&!stopping.get())failed("outbound",last?:java.io.IOException("No outbound RFCOMM candidate"))
                    }
                }
                val selected=withTimeout(65_000){winner.await()}
                currentCoroutineContext().ensureActive()
                selected
            }finally{
                stopping.set(true);winner.cancel();activeOutbound.get()?.let{runCatching{it.close()}}
                listeners.forEach{(_,srv)->r.release(srv)}
                activeOutbound.get()?.takeIf{it!==winnerSocket.get()}?.let{r.release(it)}
                if(!currentCoroutineContext().isActive)winnerSocket.get()?.let{r.release(it)}
                // Socket closure releases blocking accept/connect before joining workers.
                withContext(NonCancellable){workers.forEach{it.cancel()};workers.forEach{it.join()}}
            }
        }
    }
    private data class ControlResult(val wifi:WifiBootstrap?,val identification:AcceptedIdentification)
    fun negotiate(link:IapLink,phoneMac:String,deviceName:String,identity:PairIdentity,previous:WifiBootstrap?=null,
                  experimentalIntegrityOnly:Boolean=false,handoffWaitMs:Long=30_000L,log:(String)->Unit,
                  onNowPlayingCommand:((Int,IapFields)->Boolean)?=null,
                  onDigitalKeyRequest:DigitalKeyMatcher?=null,
                  onDeviceWifiInfoRequest:DeviceWifiInfoProvider?=null,
                  onCarPlayStartRequest:CarPlayStartRequest?=null,
                  onWifiAnnouncement:WifiAnnouncementHandler?=null,
                  identificationWaitMs:Long=10_000L,
                  networkHandoff:IapNetworkHandoff?=null):WifiBootstrap =
        requireNotNull(negotiateSession(link,phoneMac,deviceName,identity,previous,experimentalIntegrityOnly,false,log,handoffWaitMs,
            onNowPlayingCommand,onDigitalKeyRequest,onDeviceWifiInfoRequest,onCarPlayStartRequest,onWifiAnnouncement,identificationWaitMs,networkHandoff).wifi)

    /** A target Link owns fresh authentication and capabilities; it never inherits Bluetooth state. */
    fun negotiateRuntime(link:IapLink,phoneMac:String,deviceName:String,identity:PairIdentity,
                         experimentalIntegrityOnly:Boolean=false,
                         onIdentificationReady:((AcceptedIdentification)->Unit)?=null,
                         log:(String)->Unit):CapabilityRegistry {
        val accepted=negotiateRuntimeIdentification(link,phoneMac,deviceName,identity,experimentalIntegrityOnly,log)
        try{
            onIdentificationReady?.invoke(accepted)
            return accepted.capabilities
        }catch(t:Exception){accepted.invalidate();throw t}
    }
    internal fun negotiateRuntimeIdentification(link:IapLink,phoneMac:String,deviceName:String,identity:PairIdentity,
                         experimentalIntegrityOnly:Boolean=false,log:(String)->Unit):AcceptedIdentification =
        negotiateSession(link,phoneMac,deviceName,identity,null,experimentalIntegrityOnly,true,log).identification
    private fun negotiateSession(link:IapLink,phoneMac:String,deviceName:String,identity:PairIdentity,previous:WifiBootstrap?=null,
                  experimentalIntegrityOnly:Boolean,runtimeSession:Boolean,log:(String)->Unit,handoffWaitMs:Long=30_000L,
                  onNowPlayingCommand:((Int,IapFields)->Boolean)?=null,
                  onDigitalKeyRequest:DigitalKeyMatcher?=null,
                  onDeviceWifiInfoRequest:DeviceWifiInfoProvider?=null,
                  onCarPlayStartRequest:CarPlayStartRequest?=null,
                  onWifiAnnouncement:WifiAnnouncementHandler?=null,
                  identificationWaitMs:Long=10_000L,
                  networkHandoff:IapNetworkHandoff?=null):ControlResult {
        val deadline=System.nanoTime()+HANDSHAKE_DEADLINE_MS*1_000_000
        var restarts=0
        while(true){
            val attemptGeneration=link.generation
            val attemptEpoch=link.linkEpoch
            try{
                return negotiateSessionOnce(link,phoneMac,deviceName,identity,previous,
                    experimentalIntegrityOnly,runtimeSession,log,handoffWaitMs,onNowPlayingCommand,
                    onDigitalKeyRequest,onDeviceWifiInfoRequest,onCarPlayStartRequest,onWifiAnnouncement,
                    identificationWaitMs,networkHandoff,deadline)
            }catch(t:Throwable){
                val changed=link.generation!=attemptGeneration||link.linkEpoch!=attemptEpoch
                if(!changed)throw t
                if(restarts>=MAX_BOOTSTRAP_LINK_RESTARTS||System.nanoTime()>=deadline)throw BootstrapLinkRestart(t)
                // IapLink performs same-socket resynchronization before exposing the changed
                // generation to its reader. If no control session is ready here, the peer only
                // invalidated the old attempt; do not block Bootstrap waiting for an unbounded
                // future SYN or let an old rejection write into the next epoch.
                if(link.negotiatedControlSession==null)throw BootstrapLinkRestart(t)
                restarts++
                networkHandoff?.rebind(link.generation,link.linkEpoch)
                log("iAP bootstrap restart #"+restarts+" oldGeneration="+attemptGeneration+
                    " oldEpoch="+attemptEpoch+" newGeneration="+link.generation+
                    " newEpoch="+link.linkEpoch+" next=AUTH-IDENTIFICATION")
            }
        }
    }

    private fun negotiateSessionOnce(link:IapLink,phoneMac:String,deviceName:String,identity:PairIdentity,previous:WifiBootstrap?=null,
                  experimentalIntegrityOnly:Boolean,runtimeSession:Boolean,log:(String)->Unit,handoffWaitMs:Long=30_000L,
                  onNowPlayingCommand:((Int,IapFields)->Boolean)?=null,
                  onDigitalKeyRequest:DigitalKeyMatcher?=null,
                  onDeviceWifiInfoRequest:DeviceWifiInfoProvider?=null,
                  onCarPlayStartRequest:CarPlayStartRequest?=null,
                  onWifiAnnouncement:WifiAnnouncementHandler?=null,
                  identificationWaitMs:Long=10_000L,
                  networkHandoff:IapNetworkHandoff?=null,
                  handshakeDeadlineNanos:Long=System.nanoTime()+HANDSHAKE_DEADLINE_MS*1_000_000):ControlResult {
        require(handoffWaitMs in 1..30_000L)
        // Existing local budget, not an inferred Apple timeout. Tests may only shorten it.
        require(identificationWaitMs in 1..10_000L)
        // Explicit experimental mode checks the current challenge signature without claiming
        // production chain trust. Missing production material belongs to AA, not transport.
        val generation=link.generation
        val linkEpoch=link.linkEpoch
        val control=requireNotNull(link.negotiatedControlSession)
        fun checkGeneration(){
            if(link.generation!=generation||link.linkEpoch!=linkEpoch||link.negotiatedControlSession==null)
                throw BootstrapLinkRestart()
        }
        checkGeneration()
        val schema=requireNotNull(IapStartupPolicy.selectSchema(IapControlSessionKind.CARPLAY,control.version)){
            "Unsupported control session version "+control.version}
        if(!experimentalIntegrityOnly)SecurityRequirements.requireAaTrust()
        val order=IapStartupPolicy.candidateStart(IapControlSessionKind.CARPLAY,control.version)
        val transactions=PeerNegotiationController(if(order==IapStartupPolicy.Order.AUTH_FIRST)
            FallbackAttempt.AUTH_FIRST else FallbackAttempt.IDENT_FIRST,
            control.id,control.version,IapControlSessionKind.CARPLAY)
        val deadline=handshakeDeadlineNanos
        var authDeadline=0L
        var identificationDeadline=0L
        var accessorySends:Set<Int> =emptySet()
        var received:Set<Int> =emptySet()
        var identified:AcceptedIdentification?=null
        val identificationContext=if(runtimeSession)IdentificationEndpointContext.AIRPLAY_IAP
            else IdentificationEndpointContext.BLUETOOTH_RFCOMM
        var handedOff=false
        var announcement:WifiAnnouncement?=null
        var startConfig:IapFields?=null
        // A malformed 43/01 is a message-level failure on the firmware path. Keep the
        // authenticated iAP2 session alive so a later retransmission can still complete
        // the handoff. The raw fields are retained only after local validation succeeds;
        // the final parse still rechecks them against any 57/03 credentials.
        var startConfigValidated:WifiBootstrap?=null
        var networkHandoffConfig:WifiBootstrap?=null
        var optionalSent=false
        var announcementDeadline=0L
        var handoffDeadline=0L
        var startWaitLogged=false
        var certificateTransaction:IapAuthentication.CertificateTransaction?=null
        var cert:java.security.cert.X509Certificate?=null
        var authenticationSchema:AccessoryAuth.ChallengeSchema?=null
        var challenge:ByteArray?=null
        fun checkDeadlines(){
            val now=System.nanoTime()
            val state=transactions.context(LinkTransport.BT_RFCOMM,ConnectionDirection.OUTBOUND)
            if(now>=deadline||(authDeadline!=0L&&now>=authDeadline&&!transactions.authenticationComplete)||
                (identificationDeadline!=0L&&now>=identificationDeadline&&state.identificationState!=IdentificationState.ACCEPTED))
                throw IapStartupTimeout("iAP handshake deadline: auth="+state.authState+" identification="+state.identificationState,
                    state.firstPeerEvent==FirstPeerEvent.NONE)
        }
        fun send(id:Int,fields:List<Pair<Int,ByteArray>> = emptyList()){
            checkGeneration();checkDeadlines()
            log(ProtocolTrace.event("IAP2","RFCOMM","tx","0x"+id.toString(16),"queued","fields"+fields.size))
            link.send(id,fields,expectedGeneration=generation)
            checkGeneration();checkDeadlines()
        }
        fun perform(action:NegotiationAction){
            when(action){
                NegotiationAction.START_AUTH->{
                    authDeadline=System.nanoTime()+30_000_000_000L
                    val transaction=IapAuthentication.CertificateTransaction(generation,linkEpoch,identified?.let{accessorySends},timeoutMs=30000)
                    certificateTransaction=transaction
                    send(0xaa00,transaction.requestFields(generation,linkEpoch))
                }
                NegotiationAction.START_IDENTIFICATION->{
                    identificationDeadline=System.nanoTime()+identificationWaitMs*1_000_000L
                    send(0x1d00)
                    transactions.identificationStarted()
                }
                else->Unit
            }
        }
        /** §6.4 入站闸门：无条件清单直接放行，其余要“认证完成 + 识别完成 + 入站集合包含”。
         *  [0xaa06] 是例外：不查认证，但仍要求识别完成且在对端声明的入站集合里。
         *  固件里 0x1D03/0xAA04 没有入站处理器；本实现把它们当终止通知，放行以保留快速失败。 */
        val unconditionalInbound=setOf(0x0000,0x0004,0x0005,0x1d01,0x1d03,0x1d05,0x1d06,
            0xaa01,0xaa03,0xaa04,
            // AE00 是车机在识别完成后主动发起的 Power 组请求，不会出现在 accessorySends 里。
            // 放行它，否则被 inboundAllowed 挡掉后永远回不了 AE01。
            0xae00)
        fun inboundAllowed(id:Int):Boolean{
            if(id in unconditionalInbound)return true
            val state=transactions.context(LinkTransport.BT_RFCOMM,ConnectionDirection.OUTBOUND)
            if(state.identificationState!=IdentificationState.ACCEPTED)return false
            if(id==0xaa06)return id in accessorySends
            return transactions.ready&&id in accessorySends
        }
        fun sendOptional(){
            if(optionalSent||!transactions.ready)return
            optionalSent=true
            handoffDeadline=System.nanoTime()+handoffWaitMs*1_000_000L
            // 4e0e 参数 0 是蓝牙 MAC，参数 1 是设备唯一标识（C-0024 的 copyUniqueDeviceID 一解，
            // 与 4e0c 同源）。标识为空时只发参数 0，并在日志里说明少发了哪一个。
            val transportFields=buildList{
                add(0 to IapWire.cstring(phoneMac))
                if(identity.id.isEmpty())log("4e0e parameter 1 omitted: empty device UUID")
                else add(1 to IapWire.cstring(identity.id))
            }
            val messages=listOf(0x4e09 to listOf(0 to IapWire.cstring(deviceName)),
                0x4e0a to listOf(0 to IapWire.cstring("zh")),
                0x4e0e to transportFields,
                0x4e0d to listOf(0 to byteArrayOf(1)))
            messages.forEach{(id,fields)->if(id in received)send(id,fields)else log("Skip unadvertised "+id.toString(16))}
            if(identity.id.isNotEmpty())send(0x4e0c,listOf(0 to IapWire.cstring(identity.id)))
            else log("Skip 4e0c: empty device UUID")
            // 24A446 advertises what it can receive; if the head unit promised
            // 0x5702/0x4300 in Identify, send them regardless of the locally
            // parsed route flags, which are derived from a narrower byte range.
            if(received.contains(0x5702))send(0x5702)
            if(received.contains(0x4300))send(0x4300,listOf(1 to IapWire.fields(listOf(0 to byteArrayOf(1),1 to IapWire.cstring(phoneMac)))))
            if(runtimeSession)return
            // 24A446 creates a declaration pair only when both directions are
            // present: phone->accessory request and accessory->phone response.
            // Sending one half on a one-sided declaration leaves the bootstrap
            // waiting for a message the peer never promised to send.
            val routes=requireNotNull(identified).capabilities.networkHandoff
            if(routes.wifiAnnouncement){
                send(0x5702);announcementDeadline=System.nanoTime()+ANNOUNCEMENT_WAIT_MS*1_000_000
            }
            if(routes.carPlayStartSession){
                send(0x4300,listOf(1 to IapWire.fields(listOf(0 to byteArrayOf(1),1 to IapWire.cstring(phoneMac)))))
            }
            if(!routes.hasSupportedRoute)log("Identification accepted; no locally supported network handoff route declared")
        }
        var evidence=PeerEvidence(version=PeerVersion(controlSession=control.version))
        var profile:IapPeerProfile=IapPeerProfiles.select(evidence)
        log("iAP control schema="+schema+" session="+control.id+" version="+control.version)
        log(ProtocolTrace.event("IAP2","RFCOMM","local","control-session","accepted","v"+control.version))
        perform(transactions.preferredStart())
        try{
            while(true){
                checkGeneration();checkDeadlines()
                // Link ACK, early Wi-Fi config or remote AA/05 do not prove local authentication.
                if(transactions.ready){
                    sendOptional()
                    if(runtimeSession){
                        handedOff=true
                        return ControlResult(null,requireNotNull(identified))
                    }
                    // The production coordinator keeps consuming late messages after
                    // return. Hand off usable current-attempt credentials immediately;
                    // don't hold Android networking behind a missing4301/5703.
                    networkHandoffConfig=networkHandoff?.configuration()
                    if(networkHandoffConfig!=null){
                        log("iAP network configuration ready; handing off while endpoint events remain active")
                        break
                    }
                    val now=System.nanoTime()
                    if(startConfig!=null&&(announcement!=null||0x5702 !in received||now>announcementDeadline))break
                    val currentAnnouncement=announcement
                    if(startConfig==null&&currentAnnouncement!=null){
                        val startRequested=0x4300 in received&&0x4301 in accessorySends
                        // A parsed 5703 may intentionally be partial. It is a
                        // platform observation, not automatically usable credentials.
                        // Keep the existing local budget; another message does not renew it.
                        val networkOnlyError=runCatching{currentAnnouncement.requireNetworkOnly()}.exceptionOrNull()
                        if(networkOnlyError!=null&&now>=handoffDeadline)throw networkOnlyError
                        if(networkOnlyError==null&&(!startRequested||now>=handoffDeadline)){
                            if(startRequested)log("Requested 4301 deadline reached; evaluating 5703-only discovery")
                            break
                        }
                        if(!startWaitLogged){
                            startWaitLogged=true
                            log(if(startRequested)"5703 received; awaiting requested 4301 within handoff deadline"
                                else "5703 received but network configuration incomplete; awaiting usable handoff within original deadline")
                        }
                    }
                    // No 57/02 is not evidence of USB: a peer can answer 43/00 directly.
                    if(startConfig==null&&now>=handoffDeadline)
                        throw TransportException(if(0x4300 in received||0x5702 in received)
                            TransportErrorCategory.HANDOFF_FAILED else TransportErrorCategory.PLATFORM_UNSUPPORTED,
                            "No wireless handoff negotiated; USB Phone gadget/OTG and network platform service may be required")
                }
                val state=transactions.context(LinkTransport.BT_RFCOMM,ConnectionDirection.OUTBOUND)
                val activeDeadlines=mutableListOf(deadline)
                if(transactions.ready&&startConfig==null&&handoffDeadline!=0L)activeDeadlines+=handoffDeadline
                if(authDeadline!=0L&&!transactions.authenticationComplete)activeDeadlines+=authDeadline
                if(identificationDeadline!=0L&&state.identificationState!=IdentificationState.ACCEPTED)activeDeadlines+=identificationDeadline
                val command=link.poll(((activeDeadlines.min()-System.nanoTime())/1_000_000).coerceIn(1,500))?:continue
                checkGeneration();checkDeadlines()
                val receivedFields=command.fields
                log(ProtocolTrace.event("IAP2","RFCOMM","rx","0x"+command.id.toString(16),"received",
                    if(receivedFields==null)"raw" else "fields"+receivedFields.ordered.size))
                evidence=evidence.observing(command.id,command is IapCommand.Lingo)
                val previousProfile=profile
                profile=IapPeerProfiles.select(evidence)
                if(profile!==previousProfile)log("peer implementation switched from "+previousProfile.name+" to "+profile.name)
                val route=profile.classify(command)
                if(route is IapMessageRouter.Route.Lingo){handleLingo(profile,route.message,command.id,log);continue}
                val fields=command.fields
                if(fields==null){log("iAP unclassified payload id="+command.id.toString(16));continue}
                val pending=transactions.context(LinkTransport.BT_RFCOMM,ConnectionDirection.OUTBOUND)
                if(!inboundAllowed(command.id)){
                    log("iAP inbound gated id="+command.id.toString(16)+" auth="+transactions.authenticationComplete+
                        " ident="+pending.identificationState)
                    continue
                }
                // A-0002 / A-0015：重复或迟到的识别/认证消息只记录，不重跑识别、也不断链。
                if(command.id==0x1d01&&!transactions.canAcceptIdentification){
                    log("iAP 1d01 ignored: identification state "+pending.identificationState);continue
                }
                if(command.id==0xaa01&&cert!=null){log("iAP aa01 ignored: certificate already received");continue}
                if(command.id==0xaa03&&transactions.authenticationComplete){
                    log("iAP aa03 ignored: authentication already complete");continue
                }
                if(command.id==0xaa06&&certificateTransaction?.state!=IapAuthentication.CertificateTransaction.State.SERIAL_REQUESTED){
                    log("iAP aa06 ignored: no certificate serial request outstanding");continue
                }
                transactions.observe(PeerMessage(MessageId(command.id ushr 8,command.id and 255)))
                when(command.id){
                    0x1d01->{
                        // Validation is isolated from publication and transport. A failed
                        // accept/reject send is not another invalid-parameter transaction.
                        var rejection:List<RawParameter>?=null
                        var candidate:IdentifyInfo?=null
                        try{
                            // Core callbacks run in wire order before checking missing
                            // core fields. Power/other transport/feature validation remains
                            // deferred, not silently counted as Apple-required success.
                            val info=IapIdentificationValidation.validate(
                                IapIdentifyInfo.parse(fields,identificationContext.requiredComponent),identificationContext)
                            val deferred=IapIdentifyInfo.deferredParameterIds(fields).sorted()
                            if(deferred.isNotEmpty())log("1d01 feature validation deferred; parameterIds="+deferred)
                            candidate=info
                        }catch(t:IllegalArgumentException){
                            rejection=when(t){
                                is IdentificationParameterException->t.rejectedParameterIds.map{RawParameter(it,byteArrayOf())}
                                is IdentificationMissingParametersException->t.parameterIds.map{RawParameter(it,byteArrayOf())}
                                is IdentificationMessageValidationException->t.rejectedParameters
                                else->emptyList()
                            }
                        }
                        if(rejection!=null){
                            // Scalar/component errors are empty same-ID TLVs. Message-list
                            // errors may carry unaccounted BE16 IDs, never a reason byte.
                            send(0x1d03,rejection.map{it.id to it.value})
                            transactions.identificationRejected()
                            log("1d03 sent; awaiting corrected 1d01 on current link; parameters="+rejection.map{it.id}+
                                "; original identification deadline retained")
                        }else{
                            val info=requireNotNull(candidate)
                            transactions.identificationAccepting()
                            send(0x1d02)
                            val action=transactions.identificationAccepted(info.accessorySends.toSet(),info.accessoryReceives.toSet())
                            identified=AcceptedIdentification(generation,linkEpoch,info)
                            accessorySends=info.accessorySends.map{it.value}.toSet()
                            received=info.accessoryReceives.map{it.value}.toSet()
                            log("INFO Identify accessorySends="+ids16(accessorySends)+" receiverCanReceive="+ids16(received))
                            log("INFO Identify context="+identificationContext+" components="+info.components.map{it.kind}+
                                " carPlayEvidence="+info.componentCapabilities.carPlay+" messageFeatures="+info.validatedMessageFeatures+
                                " handoff="+info.networkHandoff)
                            perform(action)
                        }
                    }
                    0x1d06->{
                        val current=identified
                        if(current==null){
                            log("1d06 identification update before identification completed; ignored")
                        }else{
                            current.handle(command,link.generation,link.linkEpoch,log)
                        }
                    }
                    0xaa01->{
                        try {
                            require(cert==null){"Duplicate authentication certificate"}
                            if(authDeadline==0L)authDeadline=System.nanoTime()+30_000_000_000L
                            val policy=if(experimentalIntegrityOnly)
                                AccessoryAuth.CertificatePolicy.EXPERIMENTAL_CAPTURED_RSA1024_SHA1_OR_P256
                                else AccessoryAuth.CertificatePolicy.STRICT_P256
                            // 参数 1 是 raw mode：0 = 公开证书，1 = BAA 链。
                            // 24A446 对 >=2 记录 invalid auth type，但内部 raw
                            // authType 保持为 0，循环结束后仍走公开证书验证。
                            // 长度错误则是参数错误，不能静默降级成 mode 0。
                            val modeBytes=fields[1]
                            val mode=when {
                                modeBytes==null -> 0
                                modeBytes.size!=1 -> throw SecurityException("Authentication mode has invalid width")
                                else -> modeBytes[0].toInt() and 255
                            }
                            val (leaf,schema)=if(mode==1){
                                when(val trust=AppleBasicAttestationTrust.verify(fields[0],fields[2])){
                                    is AppleBasicAttestationTrust.Result.Verified->{
                                        log("BAA User chain verified: rootSha256="+AppleBasicAttestationTrust.rootSha256Hex+
                                            " authVersion="+trust.authVersion)
                                        trust.leaf to AccessoryAuth.schema(trust.leaf,trust.authVersion)
                                    }
                                    is AppleBasicAttestationTrust.Result.Rejected->
                                        throw SecurityException("BAA authentication chain rejected: "+trust.reason)
                                }
                            }else{
                                if(mode>=2)log("Authentication mode "+mode+" is outside the defined range; firmware continues with public-certificate processing")
                                val parsed=AccessoryAuth.parseAuthenticationCertificate(requireNotNull(fields[0]),policy,log)
                                // Mode 0 remains audit-only until the MFi/iAP public-root policy is
                                // implemented. It must not inherit the BAA User result.
                                val chain=AppleAccessoryTrust.parseChain(fields[2])
                                val trust=AppleAccessoryTrust.verify(parsed.certificate,chain)
                                log("accessory chain NOT authenticated (no MFi/iAP trust anchor on Android); "+
                                    "local chain consistency="+trust+" chainCerts="+chain.size)
                                parsed.certificate to parsed.schema
                            }
                            requireNotNull(certificateTransaction).acceptCertificate(leaf,schema,generation,linkEpoch)
                            cert=leaf
                            authenticationSchema=schema
                            val fresh=AccessoryAuth.challenge(leaf,schema)
                            challenge=fresh
                            send(0xaa02,listOf(0 to fresh))
                        } catch (t: Exception) {
                            // Firmware completes a failed certificate transaction with an
                            // empty AA/04 before exposing the local failure.
                            runCatching { send(0xaa04) }
                            throw t
                        }
                    }
                    0xaa03->{
                        var successSent=false
                        try {
                            val leaf=requireNotNull(cert){"got receiver signature but no certificate yet"}
                            val fresh=requireNotNull(challenge){"got receiver signature but the challenge was not sent yet"}
                            if(!AccessoryAuth.verifyChallenge(leaf,fresh,requireNotNull(fields[0]),requireNotNull(authenticationSchema)))
                                throw SecurityException("receiver challenge signature invalid")
                            fresh.fill(0);challenge=null
                            log("Accessory challenge signature verified; Apple root trust NOT verified")
                            send(0xaa05)
                            successSent=true
                            // Production and experimental verification are separate protocol states.
                            // The firmware-side challenge check does not turn a production session
                            // into an experimental one; only the explicitly selected compatibility
                            // mode may use EXPERIMENTAL_INTEGRITY.
                            perform(transactions.authenticationVerified(experimentalIntegrityOnly=experimentalIntegrityOnly))
                        } catch (t: Exception) {
                            if(!successSent)runCatching{send(0xaa04)}
                            throw t
                        }
                    }
                    0xaa06->{
                        val request=requireNotNull(certificateTransaction).onSerial(fields,generation,linkEpoch)
                        send(0xaa00,request)
                    }
                    // Power 组 AE00：车机请求启动外接配件会话（StartExternalAccessorySession）。
                    // 24A446 规则表把 AE00/AE01 列为 required 对，只有 AE00 没有 AE01 时车机会
                    // 认为会话没建立。实测 MyLink 在发出 AE00 后约 1.2s 主动拆掉 RFCOMM，
                    // 而此前 4e0e 恰好卡在这个时间窗内。应答载荷格式研究文档仍标 OPEN，
                    // 这里先回一个空参数应答，把链路保活，观察车机后续行为。
                    0xae00->{
                        send(0xae01)
                        log("AE01 sent in reply to AE00 (StartExternalAccessorySession); payload format still OPEN")
                    }
                    0xaa04->throw SecurityException("Accessory authentication rejected")
                    // A peer 1D03 remains a local terminal policy; it is not the
                    // successful local 1D03 -> corrected 1D01 transaction above.
                    0x1d03->throw java.io.IOException("Accessory rejected "+command.id.toString(16))
                    0x1d05->{
                        if(transactions.cancelIdentification())throw java.io.IOException("Accessory rejected 1d05 (identification cancelled)")
                        log("iAP 1d05 ignored: identification state "+pending.identificationState)
                    }
                    // 车机要求本机出示设备证书（aa10）或挑战响应（aa12）：这是 device authentication 的镜像方向，
                    // 与 aa00-aa06（车机出示、本机验证）相反。本机没有可出示的证书，默认跳过；真被索取时不伪造
                    // 应答，直接报错——静默忽略会表现成握手停住，空应答会被对端当成认证通过。
                    in DeviceAuthPolicy.requestIds->{
                        val reason=DeviceAuthPolicy.refusal(command.id)!!
                        log("Device authentication requested id=0x"+command.id.toString(16)+" provisioned="+DeviceAuthPolicy.provideCertificate+": "+reason)
                        throw SecurityException(reason)
                    }
                    // 车机对本机设备认证的判定结果：能力默认关闭，正常情况下不会出现；真收到只记录。
                    DeviceAuthPolicy.DEVICE_AUTHENTICATION_FAILED,
                    DeviceAuthPolicy.DEVICE_AUTHENTICATION_SUCCEEDED->
                        log("Device authentication result id=0x"+command.id.toString(16)+" (capability disabled locally; recorded only)")

                    0x5700->{
                        if(!transactions.ready||command.id !in accessorySends){
                            log("device Wi-Fi info request rejected by iAP2 identification gate; no 5701 emitted")
                        }else if(0x5701 !in received){
                            log("device Wi-Fi info request has no declared 5701 response; no 5701 emitted")
                        }else{
                            val result=runCatching{onDeviceWifiInfoRequest?.invoke()}.getOrElse{
                                log("device Wi-Fi info provider failed ("+it.javaClass.simpleName+"); no 5701 emitted")
                                null
                            }
                            if(result==null){
                                log("device Wi-Fi info request accepted for platform handling; no 5701 emitted without snapshot/consent")
                            }else{
                                val response=buildList<Pair<Int,ByteArray>>{
                                    add(0 to byteArrayOf((result.status and 255).toByte()))
                                    if(result.status==0){
                                        result.security?.let{add(1 to byteArrayOf(it.toByte()))}
                                        result.ssid?.let{add(2 to IapWire.cstring(it))}
                                        result.passphrase?.let{add(3 to IapWire.cstring(it))}
                                    }
                                }
                                send(0x5701,response)
                                log("device Wi-Fi info response sent status="+(result.status and 255)+
                                    " optional="+(response.size-1))
                            }
                        }
                    }
                    0x5703->if(transactions.ready&&command.id in accessorySends){
                        // Firmware accepts an empty 5703 body and still dispatches
                        // it to the platform. It is not a usable Wi-Fi snapshot,
                        // so keep it out of announcement-based endpoint selection.
                        if(fields.isEmpty()){
                            runCatching{onWifiAnnouncement?.invoke(null)}.onFailure{
                                log("5703 empty announcement platform callback failed ("+it.javaClass.simpleName+")")
                            }
                            log("5703 empty announcement dispatched to platform; no credentials produced")
                        }else{
                            // Known field errors drop only this message; they do not
                            // terminate an already authenticated iAP2 session.
                            val parsed=runCatching{WifiAnnouncement.parse(fields,log)}.getOrElse{
                                log("5703 announcement rejected ("+it.javaClass.simpleName+"); continuing with 4301")
                                null
                            }
                            if(parsed!=null){
                                announcement=parsed
                                networkHandoff?.announcement(parsed)
                                runCatching{onWifiAnnouncement?.invoke(parsed)}.onFailure{
                                    log("5703 announcement platform callback failed ("+it.javaClass.simpleName+")")
                                }
                            }
                        }
                    }
                    0x4301->if(transactions.ready&&command.id in accessorySends){
                        // Firmware records the connection event before decoding the
                        // payload. A decode error drops this one message and continues
                        // waiting on the already authenticated link.
                        log("4301 connection event received before parse")
                        if(fields.isEmpty()){
                            // Empty 4301 is a valid firmware dispatch to
                            // startSession, but it cannot produce a local endpoint.
                            runCatching{onCarPlayStartRequest?.invoke(fields)}.onFailure{
                                log("4301 empty start platform callback failed ("+it.javaClass.simpleName+")")
                            }
                            log("4301 empty start dispatched to platform; no endpoint produced")
                        }else{
                            val normalized=try{StartSessionSyntax.normalize(fields)}
                            catch(t:StartSessionConfigurationException){
                                log("4301 rejected: field="+t.fieldPath+" reason="+t.problem.name+
                                    " bytes="+t.actualBytes+"; keeping iAP2 session alive")
                                null
                            }
                            if(normalized==null)continue
                            networkHandoff?.startRequest(fields)
                            // Firmware dispatch follows syntax success, before any
                            // Android-only usable-endpoint policy. Preserve raw order
                            // for the observer; never expose a malformed known field.
                            runCatching{onCarPlayStartRequest?.invoke(fields)}.onFailure{
                                log("4301 start platform callback failed ("+it.javaClass.simpleName+")")
                            }
                            val parsed=try{wifiConfigNormalized(normalized,null,experimentalIntegrityOnly,log)}
                            catch(t:StartSessionConfigurationException){
                                if(t.problem==StartSessionProblem.MISSING_FIELD){
                                    log("4301 partial start dispatched to platform; endpoint fields incomplete")
                                }else log("4301 local endpoint unavailable: field="+t.fieldPath+" reason="+t.problem.name+
                                    " bytes="+t.actualBytes+"; keeping iAP2 session alive")
                                null
                            }catch(t:Exception){
                                log("4301 local endpoint unavailable ("+t.javaClass.simpleName+"); keeping iAP2 session alive")
                                null
                            }
                            if(parsed!=null){
                                startConfig=fields
                                startConfigValidated=parsed
                                log("4301 accepted after local validation")
                            }
                        }
                    }
                    0x4302->if(transactions.ready&&command.id in accessorySends){
                        // Firmware forwards only parameter-0 key IDs to the platform;
                        // it does not echo them and does not construct 4303 here.
                        val ids=runCatching{
                            fields.ordered.filter{it.first==0}.map{IapWire.text(it.second)}
                        }.getOrElse{
                            log("4302 key-id list rejected (invalid parameter 0); no 4303 emitted")
                            null
                        }
                        if(ids!=null){
                            fields.ordered.filter{it.first!=0}.forEach{(id,_) ->
                                log("4302 unknown parameter "+id+" ignored")
                            }
                            val matched=runCatching{onDigitalKeyRequest?.invoke(ids)}.getOrElse{
                                log("4302 digital-key matcher failed ("+it.javaClass.simpleName+"); no 4303 emitted")
                                null
                            }
                            if(matched!=null){
                                // The callback type is already String-only; an empty
                                // result intentionally produces a parameterless 4303.
                                send(0x4303,matched.map{0 to IapWire.cstring(it)})
                                log("4303 digital-key result sent count="+matched.size)
                            }else if(onDigitalKeyRequest==null)
                                log("4302 digital-key matcher unavailable; no 4303 emitted")
                        }
                    }
                    // 电话/通信状态订阅（第 15 章 §2.2/§2.3）：接受并记录字段集。没有通话状态来源时
                    // 不主动发 4155/4158，但也不能再当"未知命令"丢弃，否则车机侧永远等不到订阅生效。
                    0x4154->log("phone call-state subscription accepted="+PhoneSubscriptions.startCallStateUpdates(fields)+
                        " fields="+PhoneSubscriptions.callStateFields.sorted()+" defaultSet="+PhoneSubscriptions.callStateDefaultSet)
                    0x4156->{PhoneSubscriptions.stopCallStateUpdates();log("phone call-state subscription stopped")}
                    0x4157->log("phone communication subscription accepted="+PhoneSubscriptions.startCommunicationUpdates(fields)+
                        " fields="+PhoneSubscriptions.communicationFields.sorted())
                    0x4159->{PhoneSubscriptions.stopCommunicationUpdates();log("phone communication subscription stopped")}
                    // 导航路线引导（第 16 章 §2.1/§2.4）：5200 开始、5203 停止。
                    // 两个 handler 都先经过 feature 17 + navMainList 的四条必需消息闸门；
                    // 5204 是可选项。解析失败按固件"整条拒绝、不回应、不改状态"处理，只记日志。
                    0x5200->{
                        if(!NavigationGuidance.featureReady(accessorySends,received)){
                            log("navigation start rejected: feature 17 required message group incomplete")
                        }else{
                            val started=NavigationGuidance.start(fields)
                            if(started==null)log("navigation start rejected")
                            else log("navigation start components="+started.components+" mask="+started.mask)
                        }
                    }
                    0x5203->{
                        if(!NavigationGuidance.featureReady(accessorySends,received))
                            log("navigation stop rejected: feature 17 required message group incomplete")
                        else if(NavigationGuidance.stop(fields))
                            log("navigation stop components="+NavigationGuidance.components)
                        else log("navigation stop rejected")
                    }
                    // 媒体库（第 17 章 §2.5–§2.9）：4c00/4c02 是库信息开关，4c03/4c05 是库更新开关。
                    // 没有媒体库数据源时，4c00 之后回一条**空库**的 4c01——文档明确"空库也发一条空消息"。
                    0x4c00->{MediaLibrary.startInfo();log("media library info started")
                        send(0x4c01);log("media library info sent (empty library)")}
                    0x4c02->{MediaLibrary.stopInfo();log("media library info stopped")}
                    0x4c03->{
                        val started=MediaLibrary.startUpdates(fields)
                        if(started==null)log("media library updates rejected")
                        else log("media library updates uid="+started.libraryUid+" revision="+started.lastRevision+
                            " itemProps="+started.mediaItemProperties.size+" playlistProps="+started.playlistProperties.size+
                            " contentProps="+started.playlistContentProperties.size+" options="+started.playlistOptions)
                    }
                    0x4c05->{val stopped=MediaLibrary.stopUpdates(fields)
                        log(if(stopped)"media library updates stopped" else "media library update stop rejected (unknown libraryUID)")}
                    0x4c06->log(if(MediaLibrary.playCurrentSelection(fields))"media library play-current accepted (no platform action)"
                        else "media library play-current rejected")
                    0x4c07->log(if(MediaLibrary.playItems(fields))"media library play-items accepted (no platform action)"
                        else "media library play-items rejected")
                    0x4c08->log(if(MediaLibrary.playCollection(fields))"media library play-collection accepted (no platform action)"
                        else "media library play-collection rejected")
                    0x4c09->log(if(MediaLibrary.playAllSongs(fields))"media library play-all-songs accepted (no platform action)"
                        else "media library play-all-songs rejected")
                    // 数字音频通路（第 17 章 §2.15–§2.17）：da00 开、da02 关，都是无参数。
                    0xda00->{DigitalAudioAndDestination.startDigitalAudio();log("digital audio started (no platform source yet)")}
                    0xda02->{DigitalAudioAndDestination.stopDigitalAudio();log("digital audio stopped")}
                    // 目的地共享（第 16 章 §2.9–§2.12）：10da 开始、10dc 停止、10dd 状态回报。
                    0x10da->if(!DigitalAudioAndDestination.startDestination(fields))log("destination start rejected")
                        else log("destination sharing started")
                    0x10dc->{val stopped=DigitalAudioAndDestination.stopDestination()
                        log(if(stopped)"destination sharing stopped" else "destination stop rejected (feature 0x17 unavailable)")}
                    0x10dd->if(!DigitalAudioAndDestination.destinationStatusUpdate(fields))log("destination status rejected")
                        else log("destination status failed="+DigitalAudioAndDestination.destinationFailed+
                            " keys="+DigitalAudioAndDestination.destinationReasonKeys)
                    // 5000/5002 是"开始/停止 Now Playing 更新"的订阅命令（第 17 章 §2.1/§2.3）。
                    // 它们可能在识别阶段就到达，交给 Now Playing 发布器；没有接收方时仍按未知命令记录。
                    0x5000,0x5002,0x5003->if(onNowPlayingCommand?.invoke(command.id,fields)!=true)
                        log("Unsupported handshake command "+command.id.toString(16)+"; ignored")
                    // VoiceOver 全族（5601–5613）：本实现没有 VoiceOver 后端，明确记录并忽略，
                    // 不伪造应答，也不当作未知命令静默丢弃。
                    in 0x5601..0x5613->log("VoiceOver message 0x"+command.id.toString(16)+" unsupported (no VoiceOver backend)")
                    in IapWirelessPairing.Message.ids->if(evidence.observedMessageIds.count{it in IapWirelessPairing.Message.ids}<=1)
                        log(IapWirelessPairing.unsupported(command.id)!!)
                    else->log("Unsupported handshake command "+command.id.toString(16)+"; ignored")
                }
            }
            val wifi=networkHandoffConfig?.copy(receiverCanReceive=received)?:if(startConfig!=null){
                // Recheck against 57/03 only when that announcement exists; otherwise use
                // the snapshot already validated at message receipt.
                val parsed=if(announcement==null)startConfigValidated
                    ?:wifiConfig(startConfig, null, previous, experimentalIntegrityOnly, log)
                    else wifiConfig(startConfig,announcement,previous,experimentalIntegrityOnly,log)
                parsed.copy(receiverCanReceive=received)
            }
                else WifiBootstrap.networkOnly(requireNotNull(announcement),received)
            checkGeneration();checkDeadlines()
            val accepted=requireNotNull(identified)
            val result=ControlResult(wifi.copy(authentication=BootstrapAuthentication(generation,linkEpoch,control.version,
                aaTrusted=false,challengeSignatureVerified=transactions.authenticationComplete),identification=accepted),accepted)
            handedOff=true
            return result


        }finally{
            challenge?.fill(0)
            if(!handedOff)identified?.invalidate()
        }
    }
    /** 一条 lingo 消息：先记录**选中的实现**对它的理解，再尝试从载荷里取出 FID token。
     *
     * 载体位置是推断：文档给了 token 的字节布局（§4），却没说明它装在哪一层。切不出来就只记录、
     * 不做猜测；切出来的 `0x04`（EA 协议）交给 profile 决策，而不是在调用点写死一个协议名。 */
    private fun handleLingo(profile:IapPeerProfile,lingo:IapLingo.Message,id:Int,log:(String)->Unit) {
        val action=profile.lingoAuthenticationAction(lingo.lingo,lingo.command)
        val duty=IapLingoCatalog.duty(lingo.lingo,lingo.command)
        log("iAP lingo message id="+id.toString(16)+" lingo="+lingo.lingo+"("+IapLingoCatalog.name(lingo.lingo)+
            ") command="+lingo.command.toString(16)+" profile="+profile.name+
            "${" expected="}"+profile.lingoExpectation(lingo.lingo,lingo.command)+"${" disposition="}"+duty+"${" auth disposition="}"+action)
        // 需要应答但**文档没给应答载荷**的命令：这里给出的是"还缺什么"，不是伪造一个应答。
        // 这条日志就是实机联调时"车机在等什么"的唯一线索（此前它只表现为握手超时）。
        if(duty==IapLingoCatalog.Duty.ANSWER_WITHOUT_EVIDENCE)
            log("command needs a client answer, but the answer payload is still a gap in docs (3.2/3.6); not fabricating one, recorded and continuing")
        if(duty==IapLingoCatalog.Duty.ANSWER_REQUIRES_MFI_CHIP||action==IapAuthentication.Action.SIGN)
            log("command requires a client signature; cannot answer without an MFi auth chip (spec 2.3)")
        val tokens=runCatching{FidToken.split(lingo.payload)}.getOrNull()?:return
        for(token in tokens){
            if(token.type!=FidToken.EA_PROTOCOL){
                log("iAP FID token type="+token.type+" bytes="+token.content.size+" (unmapped, recorded)")
                continue
            }
            // 0x04 的内容是 [协议 ID][变长 payload]（§4.2）：要接受的是对端请求的那个标识，
            // 不是文档样本里的 com.hsae.datatransfer。
            val protocol=token.content.firstOrNull()?.let{java.lang.String.format(java.util.Locale.ROOT,"0x%02X",it.toInt() and 255)}
            val decision=profile.eaSession(protocol)
            log("iAP EA protocol declaration protocol="+protocol+" profile="+profile.name+" decision="+decision.javaClass.simpleName)
        }
    }
    /** Parses this exchange's 43/01; previous credentials never replace its session facts. */
    internal fun wifiConfig(start:IapFields,announcement:WifiAnnouncement?,previous:WifiBootstrap?,experimentalCompatibility:Boolean=false,log:(String)->Unit):WifiBootstrap {
        // Syntax is checked completely and in received order before any local
        // required-field gate. Partial requests must not conceal later bad fields.
        return wifiConfigNormalized(StartSessionSyntax.normalize(start),announcement,experimentalCompatibility,log)
    }
    /** Same-message4301 network subset. Never fills missing values from a previous
     * session or5703, and never invents an endpoint/port from usable credentials. */
    internal fun networkConfig(normalized:IapFields):WifiBootstrap {
        val wifi=StartSessionFields(normalized).group(1)
        val ssid=wifi.text(0);val password=wifi.text(1);val security=wifi.byte(4)
        val bytes=ssid.toByteArray(Charsets.UTF_8).size
        if(ssid.isBlank()||bytes>32)wifi.fail(0,StartSessionProblem.INVALID_SSID,bytes)
        if(security !in setOf(0,2,3,4))wifi.fail(4,StartSessionProblem.UNSUPPORTED_SECURITY)
        if(security!=0&&password.toByteArray(Charsets.UTF_8).size !in 8..63)
            wifi.fail(1,StartSessionProblem.INVALID_PASSPHRASE_LENGTH)
        return WifiBootstrap(ssid,password,security,null)
    }
    private fun wifiConfigNormalized(normalized:IapFields,announcement:WifiAnnouncement?,experimentalCompatibility:Boolean,log:(String)->Unit):WifiBootstrap {
        val top=StartSessionFields(normalized)
        log("4301 field lengths="+top.shape())
        val peerInfo=StartSessionPeerInfo.parse(normalized)
        val wifi=top.group(1)
        log("4301 wireless field lengths="+wifi.shape())
        val ssid=wifi.text(0);val password=wifi.text(1)
        announcement?.matches(ssid,password)
        log("Wi-Fi configuration consistency checked; 5703Present="+(announcement!=null))
        val addresses=wifi.addresses(3,experimentalCompatibility,log)
        val address=addresses.first()
        val security=wifi.byte(4)
        // Channel selection is still owned by Android. 4301 version/auth declarations
        // are validated and retained separately; they do not establish authentication.
        val channel=wifi.optional(2)?.let{raw->raw[0].toInt() and 255}
        log("4301 optional fields: channel="+channel+" "+peerInfo+"; retained, not an authentication result")
        val port=top.port(2)
        val receiver=top.text(3).also{
            if(it.isBlank()||it.length>128)top.fail(3,StartSessionProblem.INVALID_IDENTIFIER)
        }
        // v11 treated unsupported optional keys as absent hints. Actual pairing still
        // checks signed identity, Bonjour key and any persisted peer pin.
        val pub=top.keyHint(4,experimentalCompatibility,log)
        val ssidBytes=ssid.toByteArray(Charsets.UTF_8).size
        if(ssid.isBlank()||ssidBytes>32)wifi.fail(0,StartSessionProblem.INVALID_SSID,ssidBytes)
        require(security in listOf(0,2,3,4)){
            "${"receiver Wi-Fi security type "}${security}${" not implemented (implemented: 0=open 2=WPA2 3=WPA/WPA2 4=WPA3; WEP and enterprise auth are out of scope)"}"
        }
        if(security!=0)require(password.toByteArray(Charsets.UTF_8).size in 8..63){"${"receiver Wi-Fi password length "}${password.length}${" is outside 8..63 (security type "}${security}${")"}"}
        log("4301 endpoint fields validated; addressCount="+addresses.size+" security="+security+" keyPresent="+(pub!=null))
        // Construct the complete endpoint before the default startSession snapshot.
        // copy(endpoint=...) alone would otherwise retain an incomplete startSession.
        val endpoint=BootstrapEndpoint(address,port,receiver,pub,addresses=addresses,startSessionPeerInfo=peerInfo)
        val result=WifiBootstrap(ssid,password,security,endpoint)
        // Credentials may match, but ready/authentication/metadata belong to this exchange.
        // Network lease reuse must never replace the newly accepted 43/01 snapshot.
        return result
    }
    suspend fun network(context:Context,b:WifiBootstrap,r:Resources,log:(String)->Unit,onFailure:(Throwable)->Unit):NetworkPath = suspendCancellableCoroutine{cont->
        val cm=context.getSystemService(ConnectivityManager::class.java)
        val stopped=java.util.concurrent.atomic.AtomicBoolean(false)
        val completion=java.util.concurrent.atomic.AtomicBoolean(false)
        val cancellationRegistration=java.util.concurrent.atomic.AtomicReference<CallbackRegistration?>()
        fun complete(path:NetworkPath){if(!stopped.get()&&completion.compareAndSet(false,true))cont.resume(path)}
        fun reject(error:Throwable){if(completion.compareAndSet(false,true))cont.resumeWithException(error)}
        // Resource teardown can race Android's callback executor. Claim completion
        // once, rather than using a racy isActive -> resume pair on each thread.
        r.own(AutoCloseable{stopped.set(true);reject(java.io.IOException("Wi-Fi lease closed"))})
        cont.invokeOnCancellation{stopped.set(true);cancellationRegistration.get()?.close()}
        // 已经连在目标 SSID 上时直接复用现有网络：再发一次 specifier 会触发重新关联，
        // 打断正在使用的链路（现场表现为后续 TCP 连接 8 秒超时）。4301 给的凭据与此一致。
        runCatching{
            val active=cm.activeNetwork
            val caps=active?.let{cm.getNetworkCapabilities(it)}
            if(active!=null&&caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)){
                val current=(caps.transportInfo as? android.net.wifi.WifiInfo)?.ssid?.trim('"')
                val properties=cm.getLinkProperties(active)
                if(!current.isNullOrEmpty()&&current==b.ssid&&properties!=null&&
                    NetworkLinkReadiness.isReady(properties.interfaceName,properties.linkAddresses.map{it.address})){
                    val monitoring=java.util.concurrent.atomic.AtomicBoolean(true)
                    val monitor=object:ConnectivityManager.NetworkCallback(){
                        override fun onLost(network:Network){if(monitoring.get()&&!stopped.get()&&network==active)onFailure(java.io.IOException("Reused Wi-Fi lease lost"))}
                    }
                    val request=NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build()
                    val registration=r.own(CallbackRegistration(
                        {cm.registerNetworkCallback(request,monitor)},
                        {monitoring.set(false);cm.unregisterNetworkCallback(monitor)}))
                    cancellationRegistration.set(registration)
                    if(stopped.get())registration.close()
                    registration.start()
                    // Subscribe before the final snapshot so disappearance in the
                    // reuse/subscribe gap cannot silently leave an unmonitored lease.
                    val fresh=cm.getLinkProperties(active)
                    if(fresh==null||!NetworkLinkReadiness.isReady(fresh.interfaceName,fresh.linkAddresses.map{it.address})){
                        r.release(registration)
                        throw java.io.IOException("Wi-Fi reuse lease changed before monitoring")
                    }
                    log("Wi-Fi already on requested network with usable local addresses; reusing current network")
                    complete(NetworkPath(active,fresh))
                    return@suspendCancellableCoroutine
                }
            }
        }.onFailure{
            log("Wi-Fi reuse check failed: "+it.javaClass.simpleName)}
        if(stopped.get()||!cont.isActive)return@suspendCancellableCoroutine
        val spec=WifiNetworkSpecifier.Builder().setSsid(b.ssid).apply{
            when(b.security){0->Unit;2,3->setWpa2Passphrase(b.password);4->setWpa3Passphrase(b.password)}
        }.build()
        val request=NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).setNetworkSpecifier(spec).build()
        val callback=object:ConnectivityManager.NetworkCallback(){
            private var selected:Network?=null
            private var properties:LinkProperties?=null
            private var accessBlocked:Boolean?=null
            private var delivered=false
            private fun ready(){
                val n=selected?:return;val p=properties?:return
                if(stopped.get()||delivered||!cont.isActive||!NetworkLinkReadiness.isReady(p.interfaceName,p.linkAddresses.map{it.address}))return
                // A policy callback is diagnostic; attempt the selected Wi-Fi sockets even with VPN.
                delivered=true;log("Wi-Fi callbacks ready; interface="+p.interfaceName+" reportedBlocked="+accessBlocked)
                complete(NetworkPath(n,p))
            }
            override fun onAvailable(network:Network){
                if(stopped.get())return
                if(delivered&&selected!=network){onFailure(java.io.IOException("Wi-Fi network replaced"));return}
                selected=network;properties=null;accessBlocked=null
                log("Wi-Fi available; waiting for link properties")
            }
            override fun onCapabilitiesChanged(network:Network,c:NetworkCapabilities){
                if(network==selected)log("Wi-Fi capabilities: internet="+c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)+" restricted="+!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED))
            }
            override fun onLinkPropertiesChanged(network:Network,p:LinkProperties){if(network==selected){
                properties=p
                log("Wi-Fi link addresses: IPv4="+p.linkAddresses.count{it.address is Inet4Address}+" IPv6="+p.linkAddresses.count{it.address is Inet6Address})
                ready()
            }}
            override fun onBlockedStatusChanged(network:Network,blocked:Boolean){
                if(network!=selected)return
                log("Wi-Fi access blocked="+blocked);accessBlocked=blocked
                // Do not stop a live attempt on VPN/policy changes; actual socket I/O decides.
                ready()
            }
            override fun onUnavailable(){if(!stopped.get())reject(java.io.IOException("Wi-Fi request unavailable"))}
            override fun onLost(network:Network){if(!stopped.get()&&network==selected){
                val error=java.io.IOException("Wi-Fi lost")
                if(delivered)onFailure(error)else reject(error)
            }}
        }
        val registration=r.own(CallbackRegistration(
            {cm.requestNetwork(request,callback)},
            {cm.unregisterNetworkCallback(callback)}))
        r.own(AutoCloseable{
            stopped.set(true)
            registration.close()
            reject(java.io.IOException("Wi-Fi request closed"))
        })
        cancellationRegistration.set(registration)
        if(stopped.get())registration.close()
        registration.start()
    }
    fun address(properties:LinkProperties,text:String):InetAddress {
        val parsed=IpLiteral.parse(text)
        val addr=parsed.address
        if(addr is Inet6Address&&addr.isLinkLocalAddress){
            val name=requireNotNull(properties.interfaceName)
            val index=requireNotNull(NetworkInterface.getByName(name)).index
            require(parsed.scope==null||parsed.scope==name||parsed.scope==index.toString())
            return Inet6Address.getByAddress(null,addr.address,index)
        }
        return addr
    }
    fun socket(network:Network,address:InetAddress,port:Int,r:Resources,pinned:Boolean,
               onRefused:(SocketException)->Unit={},fallbackLocal:(()->InetAddress?)?=null,
               readTimeoutMs:Int=10_000):Socket {
        val socket=r.own(Socket())
        try{
            if(!bind(network,socket,pinned,onRefused)){
                // A denied Android Network mark does not prove that local car traffic cannot route.
                // Keep the source on the selected Wi-Fi; do not silently choose the VPN's address.
                val local=fallbackLocal?.invoke()?:throw TransportException(TransportErrorCategory.INTERFACE_BIND_FAILED,
                    "Permission-refused socket has no selected Wi-Fi source address")
                access{socket.bind(InetSocketAddress(local,0))}
            }
            socket.tcpNoDelay=true
            access{socket.connect(InetSocketAddress(address,port),8000)}
            socket.soTimeout=readTimeoutMs;return socket
        }
        catch(t:Throwable){runCatching{socket.close()};r.release(socket);throw t}
    }
    private fun access(block:()->Unit){
        try{block()}catch(t:SocketException){
            if(refused(t))
                throw SecurityException("系统拒绝访问车机 Wi-Fi 网络；请检查 VPN 的始终开启/阻止直连设置、应用 WLAN 联网权限，以及 Android 17 及以上的本地网络权限授权。原始错误："+t.message,t)
            throw t
        }
    }
    /** EPERM/EACCES is the system refusing the operation, not the car being unreachable. */
    private fun refused(t:SocketException)=t.message?.contains("EPERM")==true||t.message?.contains("EACCES")==true
    /** False means Android refused the Network mark with EPERM/EACCES. The caller must bind a
     * selected Wi-Fi source address before continuing; all other binding errors remain fatal. */
    fun bind(network:Network,socket:Socket,pinned:Boolean,onRefused:(SocketException)->Unit={}):Boolean =
        pin(pinned,onRefused){network.bindSocket(socket)}
    fun bind(network:Network,socket:DatagramSocket,pinned:Boolean,onRefused:(SocketException)->Unit={}):Boolean =
        pin(pinned,onRefused){network.bindSocket(socket)}
    internal fun pin(pinned:Boolean,onRefused:(SocketException)->Unit,block:()->Unit):Boolean {
        if(!pinned)throw TransportException(TransportErrorCategory.INTERFACE_BIND_FAILED,
            "This CarPlay schema requires binding sockets to the selected network; enable network binding")
        try{block();return true}
        catch(t:SocketException){
            if(refused(t)){onRefused(t);return false}
            throw TransportException(TransportErrorCategory.INTERFACE_BIND_FAILED,"Socket could not bind to the selected CarPlay network",t)
        }
    }
}
