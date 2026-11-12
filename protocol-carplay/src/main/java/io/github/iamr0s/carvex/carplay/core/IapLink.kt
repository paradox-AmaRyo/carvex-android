package io.github.iamr0s.carvex.carplay.core
import java.io.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean

/** 一条 iAP2 控制会话消息的两种载荷形态：TLV 字段列表，或 iAP1 风格的 lingo 包（`0x55`）。
 *  分类必须发生在解析**之前** —— TLV 解析器吃不下 lingo 载荷，否则会抛异常把整条链路带下去。 */
sealed interface IapCommand {
    val id:Int
    /** TLV 字段；lingo 载荷时为 null。 */
    val fields:IapFields?

    data class Fields(override val id:Int,val value:IapFields):IapCommand {
        override val fields:IapFields get()=value
    }

    data class Lingo(override val id:Int,val message:IapLingo.Message):IapCommand {
        override val fields:IapFields? get()=null
    }

    /** iAP2 link CMD frame (flags bit2), not a CSM/TLV message.
     *  Firmware 24A446 routes these frames before CSM reassembly.  For the
     *  two established time-sync opcodes, [fsmEvent] records the native FSM
     *  event (0x54 -> 9, 0x55 -> 10); timestamp conversion remains OPEN. */
    data class Control(override val id:Int,val opcode:Int,val body:ByteArray,
                       val frame:IapWire.Frame,val fsmEvent:Int?=null,
                       val timingContextRequired:Boolean=false):IapCommand {
        override val fields:IapFields? get()=null
    }
}

/** One outstanding frame; reader alone owns inbound sequence and CSM reassembly. */
class IapLink(input:InputStream, private val output:OutputStream,
              private val log:(String)->Unit, private val failure:(Throwable)->Unit,
              private val localMaxTxFrameBytes:Int=65535,private val localMaxRxFrameBytes:Int=65535,
              private val eakSchema:EakSchema=EakSchema.EAK_RECEIVED_LIST_V1,
              private val localReceiveWindow:Int=1,
              private val localRetransmitTimeoutMs:Int=1000,
              private val localCumulativeAckTimeoutMs:Int=10,
              private val localMaxRetransmissions:Int=30,
              private val localMaxCumulativeAck:Int=0,
              /** 打开后等对端开口的时限；到点仍无任何字节就发一次 Detect（指南 §3.3 的 T_first_byte）。 */
              private val firstByteTimeoutMs:Int=2000,
              /** 首字节时限之后等首个 SYN 的时限；到期还没有 SYN 就判 NO_SYN 并拆链（T_detect）。 */
              private val detectTimeoutMs:Int=5000):AutoCloseable {
    /** EAK body is a list of received PSNs; missing PSNs are derived locally. */
    enum class EakSchema { UNSUPPORTED, EAK_RECEIVED_LIST_V1 }
    enum class SynchronizationSchema { LINK_SYNC_V1_RELIABLE, LINK_SYNC_V1_IMMEDIATE_ACK }
    init {
        require(localMaxTxFrameBytes in 23..65535&&localMaxRxFrameBytes in 23..65535&&localReceiveWindow in 1..32)
        require(localRetransmitTimeoutMs in 20..32767&&localCumulativeAckTimeoutMs in 10..32767)
        require(localMaxRetransmissions in 1..30&&localMaxCumulativeAck in 0..127&&localMaxCumulativeAck<=localReceiveWindow)
        require(firstByteTimeoutMs in 0..60_000&&detectTimeoutMs in 0..60_000)
    }
    private val input=PushbackInputStream(input,2)
    private val started=AtomicBoolean(false)
    private val consumerLock=Any()
    private val closed=AtomicBoolean(false)
    private val incoming=LinkedBlockingQueue<IapCommand>(64)
    private val deferred=java.util.ArrayDeque<IapCommand>(); private val writeLock=Any()
    /** Guards [deferred] on its own: a re-synchronization must clear it without taking [consumerLock],
     *  because the caller waiting in [await] holds that lock for the whole wait. */
    private val deferredLock=Any()
    private val ackLock=Object()
    /** Receive-side ACK policy negotiated from the local SYN offer. 24A446 does
     * not necessarily emit a pure ACK for every ordered frame: maxAck=0 means
     * immediate ACK, otherwise the cumulative distance or ack_ms timer wins. */
    private val ackScheduler=Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task,"iap2-ack").apply{isDaemon=true}
    }
    private var ackTask:ScheduledFuture<*>?=null
    private var ackPending=false
    private var sentAck=0
    private var ackTimeoutMs=0L
    private var maxCumulativeAck=0
    /**
     * Firmware iAP2 message APIs enqueue and return; ACK completion is a separate
     * callback path. Keep one ordered worker so frame sequence allocation and the
     * existing reliable retransmission logic remain serialized without blocking
     * the caller that submitted a control message.
     */
    private val asyncSender=Executors.newSingleThreadExecutor { task ->
        Thread(task,"iap2-tx").apply{isDaemon=true}
    }
    @Volatile private var acknowledged=-1
    @Volatile private var error:Throwable?=null
    private var sendSeq=Crypto.random.nextInt(256)
    @Volatile private var receiveSeq=0
    /** Committed packet checksum version; SYN proposals do not switch it early. */
    @Volatile private var packetVersion=1
    /** Negotiated Link version is distinct from packet checksum framing: v3 uses
     *  the v1 packet header/checksum but has v2/3 CMD semantics. */
    @Volatile private var linkVersion=1
    data class ControlSession(val id:Int,val kind:Int,val version:Int)
    /** Null until the peer has acknowledged this synchronization's initial sequence. */
    @Volatile var negotiatedControlSession:ControlSession?=null
        private set
    /** Successful link synchronizations, including the initial one; never reused after a restart. */
    @Volatile var generation:Int=0
        private set
    private var control=0
    private var controlVersion=0
    @Volatile private var synchronizationEpoch=0L
    /** Detection invalidates old transactions immediately, before the new SYN completes. */
    val linkEpoch:Long get()=synchronizationEpoch
    private val epochObservers=CopyOnWriteArrayList<()->Unit>()
    /** Revokes a dependent transaction at Detection, before waiting for a replacement SYN.
     * Registration also detects a restart between taking the snapshot and subscribing. */
    fun bindEpoch(expectedEpoch:Long,invalidated:()->Unit):AutoCloseable {
        val notified=AtomicBoolean(false)
        val observer:()->Unit={if(synchronizationEpoch!=expectedEpoch&&notified.compareAndSet(false,true))invalidated()}
        synchronized(writeLock){epochObservers.add(observer)}
        observer()
        return AutoCloseable{epochObservers.remove(observer)}
    }
    @Volatile var negotiatedSynchronizationSchema:SynchronizationSchema?=null
        private set
    private var peerSyn:IapWire.Frame?=null
    private var localSynAck:IapWire.Frame?=null
    private var receiveWindow=1
    /** Peer SYN window: bounds the ACK-relative range used to decode EAK. */
    private var peerWindow=1
    /** Connected reliable-data TX slots. The firmware keeps one owned entry per in-flight PSN;
     *  ACK/EAK actions mutate these entries without changing their PSN. */
    private data class TxSlot(val seq:Int,val payload:ByteArray,var attempts:Int=0,
                              var sentAtNanos:Long=0L,var retransmitRequested:Boolean=false)
    private val txSlots=java.util.LinkedHashMap<Int,TxSlot>()
    /** Last cumulative ACK accepted for the current generation. It is initialized to the
     *  pre-data send sequence so an ACK for the first slot advances from a known baseline. */
    private var receivedAck=-1
    private val outOfOrder=linkedMapOf<Int,IapWire.Frame>()
    private data class Synchronization(val maxOutgoing:Int,val maxPacket:Int,val retryMs:Int,
        val ackMs:Int,val retries:Int,val maxAcknowledgements:Int,val sessions:List<ControlSession>,
        val version:Int=1,val noRetransmit:Boolean=false,val extensions:Set<Int> = emptySet())
    /** Control CSM routing is separate from the peer's complete session proposal. */
    private fun controlSession(sessions:List<ControlSession>):ControlSession =
        sessions.single{it.kind==0}
    private fun sessionList(sessions:List<ControlSession>):String =
        sessions.joinToString(","){it.id.toString()+":kind"+it.kind+":v"+it.version}
    private fun synchronizationSummary(value:Synchronization):String =
        "v="+value.version+" win="+value.maxOutgoing+" mtu="+value.maxPacket+
            " retryMs="+value.retryMs+" ackMs="+value.ackMs+" retries="+value.retries+
            " maxAck="+value.maxAcknowledgements+" noRetransmit="+value.noRetransmit+
            " sessions="+sessionList(value.sessions)+" extensions="+value.extensions
    /** SYN 正文布局（固件 `iap2-mainline.md` §参数表）：
     *  0..10 固定十字节；version 1 从 10 起每 3 字节一个 session 描述符到正文末尾；
     *  version 2/3 在 10 处是**扩展数量 + 扩展字节 + session 数量**，再跟 3 字节描述符。
     *  准入条件按 ch01 §2.3：MTU≥24；可靠模式 window 1..127、retrans≥20、ack 10..32767、
     *  retries 1..30、maxAck≤127 且≤window；四项全零是**无重传模式**，允许 window≤127（含 0）。
     *  描述符：id 非零唯一、type≤4 且唯一、至少一个 type0、high_bit 必须清零（fast 不支持）。 */
    private fun synchronization(payload:ByteArray):Synchronization {
        require(payload.size>=10)
        val version=payload[0].toInt() and 255
        // 解析失败前先落一行原始字段：这样即使后面的准入 require 抛异常，也能看到对端到底发了什么
        // （link 版本、window、MTU、重传/ACK 超时、retries、maxACK 与正文头部字节）。
        log("iAP SYN body: version="+version+" window="+(payload[1].toInt() and 255)+
            " mtu="+IapWire.u16(payload,2)+" retryMs="+IapWire.u16(payload,4)+
            " ackMs="+IapWire.u16(payload,6)+" retries="+(payload[8].toInt() and 255)+
            " maxAck="+(payload[9].toInt() and 255)+" bytes="+hex(payload,0,32))
        require(version in 1..3){"Unsupported iAP link version "+version}
        fun descriptor(at:Int):ControlSession {
            val id=payload[at].toInt() and 255
            val raw=payload[at+1].toInt() and 255
            require(raw and 0x80==0){"Unsupported fast session descriptor"}
            val kind=raw and 0x7f
            require(kind<=4){"Invalid session type "+kind}
            return ControlSession(id,kind,payload[at+2].toInt() and 255)
        }
        val descriptors:List<ControlSession>
        val featureSet:Set<Int>
        if(version==1){
            featureSet=emptySet()
            require((payload.size-10)%3==0)
            descriptors=(10 until payload.size step 3).map{descriptor(it)}
        }else{
            var at=10
            require(at<payload.size){"Truncated SYN extensions"}
            val extensions=payload[at++].toInt() and 255
            require(extensions<=5){"Unsupported SYN extension count "+extensions}
            require(at+extensions<payload.size){"Truncated SYN extension bytes"}
            val featureList=(at until at+extensions).map{payload[it].toInt() and 255}
            featureSet=featureList.toSet()
            // 24A446 IsFeatureSetValid (0x1000d4ee0): empty, or both time-sync
            // opcodes and no unknown member. Native OR folding ignores duplicates,
            // but they cannot supply a missing opcode. Acceptance is not local support.
            require(featureSet.isEmpty()||featureSet==setOf(0x54,0x55)){"Invalid SYN extension set"}
            at+=extensions
            val count=payload[at++].toInt() and 255
            require(count in 1..5){"Unsupported SYN session count "+count}
            require(at+count*3==payload.size){"SYN session list length mismatch"}
            descriptors=(0 until count).map{i->descriptor(at+i*3)}
        }
        val maxOutgoing=payload[1].toInt() and 255
        val maxPacket=IapWire.u16(payload,2)
        val retransmitMs=IapWire.u16(payload,4)
        val ackMs=IapWire.u16(payload,6)
        val retries=payload[8].toInt() and 255
        val maxAck=payload[9].toInt() and 255
        require(maxPacket>=24){"SYN MTU below 24"}
        val noRetransmit=retransmitMs==0&&ackMs==0&&retries==0&&maxAck==0
        if(noRetransmit){
            require(maxOutgoing<=127){"SYN window above 127"}
        }else{
            require(maxOutgoing in 1..127){"SYN window outside 1..127"}
            require(retransmitMs>=20){"SYN retransmit timeout below 20"}
            require(ackMs in 10..32767){"SYN ACK timeout outside 10..32767"}
            require(retries in 1..30){"SYN retries outside 1..30"}
            require(maxAck<=127&&maxAck<=maxOutgoing){"SYN maxAck above 127 or above window"}
        }
        // id 非零且唯一；type 唯一；至少一个 control(type0)。
        require(descriptors.all{it.id!=0})
        require(descriptors.map{it.id}.distinct().size==descriptors.size)
        require(descriptors.map{it.kind}.distinct().size==descriptors.size)
        require(descriptors.count{it.kind==0}==1)
        val controlVersion=descriptors.single{it.kind==0}.version
        // A SYN|ACK is an on-wire commitment. Use the same supported schema policy as
        // Bootstrap before replying, not an echo followed by an upper-layer rejection.
        require(IapStartupPolicy.selectSchema(IapControlSessionKind.CARPLAY,controlVersion)!=null){
            "Unsupported control session version "+controlVersion
        }
        val result=Synchronization(maxOutgoing,maxPacket,retransmitMs,ackMs,retries,maxAck,descriptors,version,noRetransmit,featureSet)
        log("iAP SYN parsed "+synchronizationSummary(result))
        return result
    }
    private var maxPacket=localMaxTxFrameBytes
    private var retryMs=localRetransmitTimeoutMs.toLong()
    private var retryCount=localMaxRetransmissions
    /** 对端四项全零 = 无重传模式：发送不进重传队列/不排重传计时器，接收非连续 PSN 直接 RST。 */
    @Volatile private var noRetransmit=false
    private val partial=ByteArrayOutputStream()
    private var reader:Thread?=null
    @Volatile private var pendingSeq=-1
    private val syncLock=Any()
    private val resyncRequested=AtomicBoolean(false)
    @Volatile private var resyncLatch:java.util.concurrent.CountDownLatch?=null
    private var resyncCount=0
    private val maxResynchronization=3
    /** 握手兜底计时器：只覆盖“打开到首个 SYN”这一段，链路一旦进入 SYN 交换就由重传预算接管。 */
    private val handshakeDeadline=Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task,"iap-handshake-deadline").apply{isDaemon=true}
    }
    /** 24A446 Attach/ResetSYNACK resets the ACTIVE parameters (link+0x19a)
     * to SetDefaultSYNParam: 1000ms, 30 retransmissions. The proposed parameters
     * in link+0x168 do not become active until NotifyConnection. In particular,
     * a zero-retransmission proposal does not disable this pending timer.
     * These defaults are distinct from our configurable local SYN offer. */
    private val pendingSynAckTimeoutMs=1000L
    private val pendingSynAckRetryLimit=30
    /** Native send/reset count +0x1d0 and resend count +0x1d8 are independent.
     * ResetSYNACK calls Reset(..., resetCounters=false), so new peer SYNs in
     * the same attempt must not replenish the retransmission budget. */
    private class SynchronizationBudget(var proposals:Int=0,var retransmissions:Int=0)
    private class PendingSynAck(val epoch:Long,val frame:IapWire.Frame,val budget:SynchronizationBudget){
        var task:ScheduledFuture<*>?=null
        var timerGeneration=0L
    }
    /** All accesses, timer validity checks and writes are serialized by writeLock. */
    private var pendingSynAck:PendingSynAck?=null
    /** One absolute wait budget per pre-SYN period. ACK/Detection traffic must
     * not keep extending it; accepting a SYN hands ownership to its retry timer. */
    private var preSynDeadline:ScheduledFuture<*>?=null
    private var preSynDeadlineToken=0L
    @Volatile private var firstByteSeen=false
    private val idleDetectSent=AtomicBoolean(false)
    private val frames=IapFrameReader(this.input,log,{t->failLink(t)},
        detection={
            clearSynchronization()
            packetVersion=1
            linkVersion=1
            armPreSynDeadline()
            synchronized(writeLock){output.write(IapWire.detection);output.flush()}
        },packetVersion={packetVersion})
    /** Detection is a separate L1 event, including when an established peer starts over. */
    private fun clearSynchronization(){
      synchronized(writeLock){
        cancelPendingSynAck()
        negotiatedControlSession=null
        negotiatedSynchronizationSchema=null;peerSyn=null;localSynAck=null
        synchronized(ackLock){
            ackTask?.cancel(false);ackTask=null;ackPending=false
            synchronizationEpoch++
            pendingSeq=-1
            acknowledged=-1
            receivedAck=-1
            sentAck=0
            txSlots.clear()
            ackLock.notifyAll()
        }
        partial.reset();outOfOrder.clear();incoming.clear()
        synchronized(deferredLock){deferred.clear()}
        sendSeq=Crypto.random.nextInt(256);receiveSeq=0
      }
      epochObservers.forEach{it()}
    }
    private fun hex(bytes:ByteArray,offset:Int,count:Int):String {
        val end=minOf(bytes.size,offset+count)
        if(offset>=end)return ""
        val out=StringBuilder()
        for(i in offset until end)out.append((bytes[i].toInt() and 255).toString(16).padStart(2,'0'))
        return out.toString()
    }
    /** Payload bytes never enter logs: fragments may start inside a certificate or credential. */
    private fun frameLine(f:IapWire.Frame):String {
        val p=f.payload
        val id=if(f.flags and 0xa0==0&&p.size>=6&&p[0]==0x40.toByte()&&p[1]==0x40.toByte()&&IapWire.u16(p,2)>=6)
            IapWire.u16(p,4) else null
        val metadata=if(id==null)"" else " csm="+id.toString(16)
        return f.flags.toString(16)+"/"+f.seq+"/"+f.ack+"/"+f.session+"/"+p.size+metadata
    }
    private fun write(f:IapWire.Frame) = synchronized(writeLock) {
        check(!closed.get()){"iAP link closed"}
        val packet=IapWire.packet(f,packetVersion)
        require(packet.size<=localMaxTxFrameBytes)
        log("iAP frame TX "+frameLine(f))
        output.write(packet); output.flush()
        // A data/ACK frame can carry the cumulative receive ACK as a piggyback.
        // Only clear a pending ACK after the bytes were accepted by the output;
        // SYN/SYNACK acknowledgement fields during negotiation are unrelated.
        if(f.flags and 0x40!=0) synchronized(ackLock){
            if(ackPending&&f.ack==receiveSeq){
                sentAck=receiveSeq;ackPending=false
                ackTask?.cancel(false);ackTask=null
            }
        }
    }
    fun start(allowDirectSyn:Boolean=false, detectOnIdle:Boolean=true) {
        check(started.compareAndSet(false,true)){"iAP link already started"}
        armHandshakeDeadlines(detectOnIdle)
        val direct=if(allowDirectSyn){
            val prefix=IapWire.exact(input,2);input.unread(prefix)
            firstByteSeen=true
            prefix.contentEquals(byteArrayOf(-1,0x5a))
        }else false
        if(!direct){
            var matched=0; var seen=0
            while(matched<6) {
                val b=input.read(); if(b<0)throw EOFException("Before detection")
                firstByteSeen=true
                require(++seen<=4096) { "Detection byte limit" }
                matched=if(b==(IapWire.detection[matched].toInt() and 255)) matched+1 else if(b==255)1 else 0
            }
            log("iAP detection RX="+hex(IapWire.detection,0,IapWire.detection.size))
            synchronized(writeLock){output.write(IapWire.detection); output.flush()}
            log("iAP detection TX="+hex(IapWire.detection,0,IapWire.detection.size))
            log("iAP detection RX/TX")
        }else log("iAP framed packet; detection not present (flags not yet classified)")
        // 初次握手的失败同样必须走 failure 回调（链路 DEAD），不能只把异常抛给调用线程——
        // 否则上层看不到"链路已死"，还会继续往一个不会再有应答的链路里塞帧。
        try{synchronized(syncLock){exchangeSynchronization(false)}}
        catch(t:Throwable){failLink(t);throw error?:t}
        reader=Thread({
            try {
                while(!closed.get()){
                    // The read loop is this socket's only reader, so a re-synchronization has to run
                    // here: two readers on one stream would each swallow the other's bytes.
                    if(resyncRequested.getAndSet(false)){
                        log("iAP link restart requested; re-synchronizing on the same socket")
                        try{synchronized(syncLock){exchangeSynchronization(true)}}
                        finally{resyncRequested.set(false);resyncLatch?.countDown();resyncLatch=null}
                        continue
                    }
                    val frame=frames.read(localMaxRxFrameBytes)
                    // A Detection consumed inside frames.read() has already revoked
                    // the old session. ACK/data now belong to pre-SYN handling, not
                    // receive(), even if the first following packet isn't a SYN.
                    if(negotiatedControlSession==null){
                        try{synchronized(syncLock){exchangeSynchronization(true,frame)}}
                        finally{resyncRequested.set(false);resyncLatch?.countDown();resyncLatch=null}
                        continue
                    }
                    // 24A446's in-order dispatcher treats a bare RST (flags=0x10)
                    // as an invalid link-control packet.  It does not emit a
                    // compensating ACK/RST or tear down the session.  Only the
                    // exact bare form is handled here; composite flags such as
                    // 0x50 still go through normal ACK/data dispatch.
                    if(frame.flags==0x10){handleBareRst(frame);continue}
                    if(frame.flags and 0x80!=0&&frame.session==0){
                        val previous=peerSyn
                        if(previous!=null&&frame.flags==previous.flags&&frame.seq==previous.seq&&
                            frame.ack==previous.ack&&frame.payload.contentEquals(previous.payload)){
                            write(checkNotNull(localSynAck));continue
                        }
                        // 带 ACK 位的 SYN 仍是 SYN：幂等重发 SYNACK，仍等纯 ACK。
                        if(frame.flags==0xc0&&localSynAck!=null){
                            write(IapWire.Frame(0xc0,sendSeq,frame.seq,0,localSynAck!!.payload))
                            continue
                        }
                        require(frame.flags==0x80){"SYNC_RENEGOTIATION_REQUIRED"}

                        // The accessory restarted the link and sent a fresh SYN. It was consumed to get
                        // here, so it is handed to the exchange rather than read a second time.
                        log("iAP accessory re-synchronization; re-synchronizing")
                        try{synchronized(syncLock){exchangeSynchronization(true,frame)}}
                        finally{resyncRequested.set(false);resyncLatch?.countDown();resyncLatch=null}
                        continue
                    }
                    receive(frame)
                }
            }
            catch(t:Throwable) { resyncLatch?.countDown();resyncLatch=null;failLink(t) }
        },"iap-reader").apply {isDaemon=true;start()}
    }
    /** 打开到首个 SYN 的两段兜底（指南 §3.3）：
     *  - T_first_byte：`firstByteTimeoutMs` 内一个字节都没收到，就主动发一次 Detect；
     *  - T_detect：再过 `detectTimeoutMs` 仍没有对端 SYN，判 NO_SYN 并拆链。
     *  没有这一段，对端一直不说话时 `start()` 会永久阻塞在 read 上——既不失败也不重连，
     *  上层看不到任何事件。两个时限都只在握手前生效：`peerSyn` 一旦出现（含重复 SYN 的重发路径），
     *  重传与重复 SYN 预算由 [exchangeSynchronization] 接管，这里不再干预。 */
    private fun armHandshakeDeadlines(detectOnIdle:Boolean){
        if(detectOnIdle&&firstByteTimeoutMs>0)handshakeDeadline.schedule({
            if(closed.get()||firstByteSeen||handshakeComplete())return@schedule
            if(!idleDetectSent.compareAndSet(false,true))return@schedule
            log("iAP first-byte deadline "+firstByteTimeoutMs+"ms; sending Detect")
            runCatching{synchronized(writeLock){output.write(IapWire.detection);output.flush()}}
                .onFailure{log("iAP Detect write failed: "+it.javaClass.simpleName+" "+(it.message?:""))}
        },firstByteTimeoutMs.toLong(),TimeUnit.MILLISECONDS)
        armPreSynDeadline()
    }
    /** Application safety budget, NOT a recovered Apple timeout policy.
     * Also covers a Detection after the original startup timer has expired. */
    private fun armPreSynDeadline()=synchronized(writeLock){
        if(closed.get()||detectTimeoutMs<=0||preSynDeadline!=null)return@synchronized
        val budget=firstByteTimeoutMs.toLong()+detectTimeoutMs
        val token=++preSynDeadlineToken
        preSynDeadline=handshakeDeadline.schedule({
            var terminalFailure:Throwable?=null
            synchronized(writeLock){
                if(closed.get()||token!=preSynDeadlineToken||handshakeComplete())return@schedule
                val timeout=java.net.SocketTimeoutException("iAP link did not synchronize within "+budget+"ms (NO_SYN)")
                log("iAP NO_SYN: no peer SYN within "+budget+"ms; tearing the link down")
                error=timeout;close();terminalFailure=timeout
            }
            terminalFailure?.let(failure)
        },budget,TimeUnit.MILLISECONDS)
    }
    /** Caller holds writeLock; a cancelled callback cannot kill the next wait. */
    private fun cancelPreSynDeadline(){
        preSynDeadlineToken++
        preSynDeadline?.cancel(false);preSynDeadline=null
    }
    /** 对端 SYN 已到手、或握手已提交时，两段兜底都不再适用。 */
    private fun handshakeComplete():Boolean=synchronized(writeLock){peerSyn!=null||negotiatedControlSession!=null}
    /** Close and publish failure once even when the reader and a timer race. */
    private fun failLink(t:Throwable){
        val report=synchronized(writeLock){
            if(closed.get())false else{error=t;close();true}
        }
        if(report)failure(t)
    }
    private fun cancelPendingSynAck(){
        // Caller holds writeLock, including commit/reset/close.
        pendingSynAck?.let{it.timerGeneration++;it.task?.cancel(false);it.task=null}
        pendingSynAck=null
    }
    private fun armPendingSynAck(pending:PendingSynAck){
        pending.task?.cancel(false)
        val timerGeneration=++pending.timerGeneration
        pending.task=handshakeDeadline.schedule({
            var terminalFailure:Throwable?=null
            synchronized(writeLock){
                if(closed.get()||pendingSynAck!==pending||pending.epoch!=synchronizationEpoch||
                    pending.timerGeneration!=timerGeneration)return@schedule
                try{resendPendingSynAck(pending,"timer")}
                catch(t:Throwable){
                    // Mark dead before unblocking read, and while this round is
                    // still owned: a stale timer must never fail a new round.
                    error=t;close();terminalFailure=t
                }
            }
            terminalFailure?.let(failure)
        },pendingSynAckTimeoutMs,TimeUnit.MILLISECONDS)
    }
    private fun resendPendingSynAck(pending:PendingSynAck,reason:String){
        check(pendingSynAck===pending&&pending.epoch==synchronizationEpoch&&!closed.get())
        if(pending.budget.retransmissions>=pendingSynAckRetryLimit){
            log("iAP sync terminal state=retransmission-budget-exhausted epoch="+pending.epoch+
                " pendingSeq="+pending.frame.seq+" pendingAck="+pending.frame.ack+
                " proposals="+pending.budget.proposals+" retransmissions="+pending.budget.retransmissions+
                " next=final-pure-ack-or-renegotiation")
            throw java.net.SocketTimeoutException("iAP SYNACK retransmission budget exhausted (retries="+
                pendingSynAckRetryLimit+"); link dead")
        }
        pending.budget.retransmissions++
        log("iAP SYNACK retransmit #"+pending.budget.retransmissions+"/"+pendingSynAckRetryLimit+
            " reason="+reason+" epoch="+pending.epoch)
        write(pending.frame)
        armPendingSynAck(pending)
    }
    /** Pending local offer and latest peer receive limits; never used by data TX until commit. */
    private data class SynchronizationWork(val local:Synchronization,val peer:Synchronization)

    /** 24A446 CheckNegotiation: merge with CURRENT work, not the first peer
     * offer. Local receive limits remain local; peer limits track the latest
     * proposal. Preserve the ordered peer session table, while CSM routing
     * selects the unique control session separately.
     * Reliability-mode switches and native invalid-input repair remain outside
     * this bounded implementation; parsing/ACK guards are deliberately kept. */
    private fun negotiateSynchronization(peer:Synchronization,previous:SynchronizationWork?=null):SynchronizationWork {
        require(previous==null||previous.local.noRetransmit==peer.noRetransmit){"SYNC_MODE_CHANGE_UNSUPPORTED"}
        val old=previous?.local
        val local=Synchronization(
            maxOutgoing=localReceiveWindow,maxPacket=localMaxRxFrameBytes,
            retryMs=if(peer.noRetransmit)0 else minOf(old?.retryMs?:localRetransmitTimeoutMs,peer.retryMs),
            ackMs=if(peer.noRetransmit)0 else minOf(old?.ackMs?:localCumulativeAckTimeoutMs,peer.ackMs),
            retries=if(peer.noRetransmit)0 else minOf(old?.retries?:localMaxRetransmissions,peer.retries),
            maxAcknowledgements=if(peer.noRetransmit)0 else minOf(old?.maxAcknowledgements?:localMaxCumulativeAck,peer.maxAcknowledgements),
            sessions=peer.sessions,
            version=minOf(old?.version?:3,peer.version),noRetransmit=peer.noRetransmit,
            extensions=emptySet())
        return SynchronizationWork(local,peer)
    }
    private fun synchronizationPayload(local:Synchronization):ByteArray=ByteArrayOutputStream().apply{
        write(local.version);write(local.maxOutgoing);write(IapWire.be16(local.maxPacket))
        write(IapWire.be16(local.retryMs));write(IapWire.be16(local.ackMs))
        write(local.retries);write(local.maxAcknowledgements)
        if(local.version>=2){write(0);write(local.sessions.size)}
        local.sessions.forEach{write(it.id);write(it.kind);write(it.version)}
    }.toByteArray()

    /** Caller holds writeLock. A newly generated proposal owns a new PSN and
     * timer, but not a new budget. Exact duplicates use resendPendingSynAck. */
    private fun proposeSynchronization(peer:IapWire.Frame,work:SynchronizationWork,
        epoch:Long,budget:SynchronizationBudget,sequence:Int):PendingSynAck {
        check(!closed.get()&&synchronizationEpoch==epoch){"iAP synchronization changed"}
        cancelPendingSynAck()
        sendSeq=sequence;receiveSeq=peer.seq
        val response=IapWire.Frame(0xc0,sequence,peer.seq,0,synchronizationPayload(work.local))
        val pending=PendingSynAck(epoch,response,budget)
        cancelPreSynDeadline()
        peerSyn=peer;localSynAck=response;pendingSynAck=pending
        val control=controlSession(work.local.sessions)
        log("iAP sync proposal #"+(budget.proposals+1)+" epoch="+epoch+" seq="+sequence+
            " link="+work.local.version+" sessions="+sessionList(work.local.sessions)+
            " control="+control.id+" version="+control.version+" retryMs="+work.local.retryMs+
            " ackMs="+work.local.ackMs+" peerWindow="+work.peer.maxOutgoing+" peerMtu="+work.peer.maxPacket+
            " next=final-pure-ack-or-renegotiation")
        budget.proposals++
        write(response) // Still uses the committed packet framing, not the proposal.
        if(budget.proposals>10)throw IOException("iAP SYN proposal budget exhausted; link dead")
        armPendingSynAck(pending)
        return pending
    }
    private fun sameSynchronizationFrame(a:IapWire.Frame,b:IapWire.Frame):Boolean=
        a.flags==b.flags&&a.seq==b.seq&&a.ack==b.ack&&a.session==b.session&&a.payload.contentEquals(b.payload)

    /** 24A446 ProcessInOrderPacket + device state2/3, before any peer SYN:
     * - Pure ACK with unpopulated peer parameters produces event22; neither
     *   state handles it. No wire reply, no connected notification, keep waiting.
     * - Bare RST is invalid and ignored by the native packet dispatcher.
     * - ACK+data produces event15 -> SendRST, clears seq/ack, stays pre-SYN.
     * This is NOT the pending state's final-ACK handler. Never feed an orphan
     * ACK into committed sequence/CSM state, nor pretend its ack names our SYN.
     * Other forms and all SYN body validation retain the existing strict gates. */
    private fun awaitPeerSynchronization(firstFrame:IapWire.Frame?):IapWire.Frame {
        var next=firstFrame
        while(true){
            val frame=next?:frames.read(localMaxRxFrameBytes)
            next=null;firstByteSeen=true
            log("iAP frame RX "+frameLine(frame))
            if((frame.flags==0x80||frame.flags==0xc0)&&frame.session==0)return frame
            when {
                frame.flags==0x40&&frame.session==0&&frame.payload.isEmpty()->
                    log("iAP pre-SYN ACK ignored; awaiting peer SYN (parameters not negotiated)")
                frame.flags==0x10->handleBareRst(frame)
                frame.flags==0x40&&frame.payload.isNotEmpty()->{
                    log("iAP pre-SYN data rejected; sending RST and awaiting peer SYN")
                    clearSynchronization()
                    synchronized(writeLock){
                        // Native SendRST -> ResetSeqAck(...,0,0) zeros both
                        // sequence pairs; RST is session0, seq0, ack0, empty.
                        sendSeq=0
                        write(IapWire.Frame(0x10,0,0,0,byteArrayOf()))
                    }
                }
                else->throw IllegalArgumentException("Expected accessory SYN; unsupported pre-SYN frame "+frameLine(frame))
            }
        }
    }

    /** Runs the SYN exchange on the sole input reader, including same-socket recovery.
     * Fresh SYN resets the work/epoch; SYNACK continues the same work and budget. */
    private fun exchangeSynchronization(restart:Boolean,firstFrame:IapWire.Frame?=null,
        budget:SynchronizationBudget=SynchronizationBudget(),nextInitialSequence:Int?=null,
        resetInvalidAck:Boolean=false) {
        require(resyncCount<maxResynchronization){"accessory link restarted "+resyncCount+" times without success; giving up resync"}
        clearSynchronization()
        armPreSynDeadline()
        // 24A446 pending event19 -> DeviceActionSendRST -> state3. Clear the
        // proposal/timer/epoch before writing, retain the socket and retry budget.
        // RST carries zero seq/ack; sendSeq is only the fresh next SYNACK proposal,
        // not evidence that any parameters or authentication are already valid.
        if(resetInvalidAck)write(IapWire.Frame(0x10,0,0,0,byteArrayOf()))
        if(nextInitialSequence!=null)sendSeq=nextInitialSequence
        if(restart){resyncCount++;log("iAP link restart epoch="+resyncCount+"; authentication-and-readiness cleared, awaiting peer SYN")}
        var accepted=awaitPeerSynchronization(firstFrame)
        val handshakeEpoch=synchronizationEpoch
        var work=negotiateSynchronization(synchronization(accepted.payload))
        try{
            var pending=synchronized(writeLock){proposeSynchronization(accepted,work,handshakeEpoch,budget,sendSeq)}
            while(true){
                val incomingFrame=frames.read(localMaxRxFrameBytes)
                if(synchronizationEpoch!=handshakeEpoch){
                    // Detection already cancelled the old timer and invalidated its epoch.
                    exchangeSynchronization(true,incomingFrame);return
                }
                log("iAP frame RX "+frameLine(incomingFrame))
                // An exact retransmitted SYNACK acknowledges the PREVIOUS proposal.
                // Classify it before checking ACK against our newest PSN.
                if(sameSynchronizationFrame(incomingFrame,accepted)){
                    log("iAP sync classify=duplicate-peer-syn peerSeq="+incomingFrame.seq+
                        " pendingSeq="+pending.frame.seq+" action=resend-current-synack")
                    synchronized(writeLock){resendPendingSynAck(pending,"duplicate SYN")}
                    continue
                }
                if(incomingFrame.flags==0x80&&incomingFrame.session==0&&incomingFrame.seq!=accepted.seq){
                    log("iAP sync classify=fresh-peer-syn oldPeerSeq="+accepted.seq+
                        " newPeerSeq="+incomingFrame.seq+" pendingSeq="+pending.frame.seq+
                        " action=reset-synchronization")
                    exchangeSynchronization(false,incomingFrame,budget,(pending.frame.seq+1) and 255);return
                }
                if(incomingFrame.flags and 0x80!=0&&incomingFrame.seq==accepted.seq){
                    log("iAP sync classify=same-peer-seq-changed peerSeq="+incomingFrame.seq+
                        " pendingSeq="+pending.frame.seq+" action=fail")
                    throw IllegalArgumentException("SYNC_SAME_PSN_CHANGED")
                }
                // Bounded initial-handshake recovery, NOT general ACK tolerance.
                // ReadyPacket tests unsigned (lastTx-ack)&255 against ACTIVE peer
                // window. Attach defaults it to 1; the proposed peerWindow has not
                // committed yet, even for a zero-retransmission proposal. Keep the
                // existing fail-closed behavior for gap1, other packet forms and
                // post-connection resynchronization until those paths are aligned.
                val ackGap=(pending.frame.seq-incomingFrame.ack) and 255
                if(generation==0&&incomingFrame.flags==0x40&&incomingFrame.session==0&&
                    incomingFrame.payload.isEmpty()&&incomingFrame.seq==accepted.seq&&ackGap>1){
                    log("iAP sync classify=pending-ack-outside-window expected="+pending.frame.seq+
                        " received="+incomingFrame.ack+" gap="+ackGap+
                        " activePeerWindow=1; sending RST and awaiting fresh SYN on same transport")
                    exchangeSynchronization(false,budget=budget,resetInvalidAck=true)
                    return
                }
                if(incomingFrame.flags and 0x40==0||incomingFrame.ack!=pending.frame.seq){
                    log("iAP sync classify=unassociated-frame flags="+incomingFrame.flags.toString(16)+
                        " seq="+incomingFrame.seq+" ack="+incomingFrame.ack+
                        " expectedAck="+pending.frame.seq+" payloadBytes="+incomingFrame.payload.size+
                        " epoch="+handshakeEpoch+" proposals="+budget.proposals+
                        " retransmissions="+budget.retransmissions+" next=associated-synack-or-final-ack")
                }
                require(incomingFrame.flags and 0x40!=0&&incomingFrame.ack==pending.frame.seq){"Unassociated SYN ACK"}
                if(incomingFrame.flags and 0x80!=0){
                    require(incomingFrame.flags==0xc0&&incomingFrame.session==0&&incomingFrame.payload.isNotEmpty()){
                        "SYNC_RENEGOTIATION_REQUIRED"}
                    val incoming=synchronization(incomingFrame.payload)
                    val next=negotiateSynchronization(incoming,work)
                    log("iAP sync classify=renegotiation peerSeq="+incomingFrame.seq+
                        " peerAck="+incomingFrame.ack+" previousProposalSeq="+pending.frame.seq+
                        " incoming="+synchronizationSummary(incoming)+
                        " nextLocal="+synchronizationSummary(next.local)+
                        " next=final-pure-ack-or-renegotiation")
                    synchronized(writeLock){
                        check(pendingSynAck===pending&&synchronizationEpoch==handshakeEpoch&&!closed.get())
                        pending=proposeSynchronization(incomingFrame,next,handshakeEpoch,budget,(pending.frame.seq+1) and 255)
                    }
                    work=next;accepted=incomingFrame
                    // Native state4 events4 AND6 send SYNACK and remain pending.
                    // Even an unchanged SYNACK is not the pure confirmation event21.
                    continue
                }
                if(!(incomingFrame.flags==0x40&&incomingFrame.session==0&&
                    incomingFrame.payload.isEmpty()&&incomingFrame.seq==accepted.seq)){
                    log("iAP sync classify=invalid-final-confirmation flags="+incomingFrame.flags.toString(16)+
                        " seq="+incomingFrame.seq+" ack="+incomingFrame.ack+
                        " expectedPeerSeq="+accepted.seq+" payloadBytes="+incomingFrame.payload.size+
                        " pendingSeq="+pending.frame.seq+" action=fail")
                }
                require(incomingFrame.flags==0x40&&incomingFrame.session==0&&
                    incomingFrame.payload.isEmpty()&&incomingFrame.seq==accepted.seq){"SYNC_CONFIRMATION_INVALID"}
                synchronized(writeLock){
                    check(!closed.get()&&pendingSynAck===pending&&synchronizationEpoch==handshakeEpoch)
                    cancelPendingSynAck()
                    val local=work.local
                    val session=controlSession(local.sessions)
                    maxPacket=minOf(work.peer.maxPacket,localMaxTxFrameBytes)
                    receiveWindow=local.maxOutgoing;peerWindow=work.peer.maxOutgoing
                    noRetransmit=local.noRetransmit
                    retryMs=local.retryMs.toLong();retryCount=local.retries
                    ackTimeoutMs=local.ackMs.toLong();maxCumulativeAck=local.maxAcknowledgements
                    control=session.id;controlVersion=session.version
                    packetVersion=local.version;linkVersion=local.version
                    synchronized(ackLock){sentAck=receiveSeq;ackPending=false;ackTask?.cancel(false);ackTask=null}
                    negotiatedSynchronizationSchema=if(local.maxAcknowledgements==0)
                        SynchronizationSchema.LINK_SYNC_V1_IMMEDIATE_ACK else SynchronizationSchema.LINK_SYNC_V1_RELIABLE
                    generation++
                    // Publish the ready marker LAST, after all active fields.
                    negotiatedControlSession=session
                    log("iAP sync classify=final-confirmation peerSeq="+accepted.seq+
                        " peerAck="+pending.frame.seq+" action=commit next=AUTH-IDENTIFICATION")
                    log("iAP synchronized session="+control+" version="+controlVersion+" maxPacket="+maxPacket+
                        " proposals="+budget.proposals+" epoch="+handshakeEpoch)
                }
                return
            }
        }finally{
            synchronized(writeLock){if(pendingSynAck?.epoch==handshakeEpoch)cancelPendingSynAck()}
        }
    }
    /** Ask for a re-synchronization on the same socket and wait for it. The read loop performs it when one
     *  is running, so the caller never becomes a second reader of the stream; waiting is what makes a
     *  re-handshake safe to start right after this returns. */
    fun restart(timeoutMs:Long=10000) {
        check(started.get()){"iAP link not started"}
        check(!closed.get()){"iAP link closed"}
        if(reader==null){synchronized(syncLock){exchangeSynchronization(true)};return}
        val latch=java.util.concurrent.CountDownLatch(1)
        resyncLatch=latch
        resyncRequested.set(true)
        // 超时必须把请求与 latch 一起收回：read 循环用 resyncRequested.getAndSet(false) 消费请求，
        // 若这里抛异常却把 resyncRequested 留在 true，循环稍后会在无人等待的情况下做一次多余重同步，
        // 并 countDown 一个已经没人持有的 latch（resyncCount 也会被白白消耗一次，三次即放弃整条链路）。
        val completed=try{latch.await(timeoutMs,TimeUnit.MILLISECONDS)}catch(t:InterruptedException){
            resyncRequested.set(false);resyncLatch=null;throw t}
        if(!completed){
            resyncRequested.set(false);resyncLatch=null
        }
        check(completed){"${"iAP link re-synchronization timed out after "}${timeoutMs}${"ms"}"}
    }
    /** 24A446 `iAP2LinkProcessInOrderPacket` classifies bare RST (0x10)
     *  as an invalid control packet.  The recovered run-once vector leaves
     *  the FSM and wire output unchanged, so do not synthesize ACK/RST here.
     *  Composite flags are deliberately handled by [receive] instead. */
    private fun handleBareRst(f:IapWire.Frame){
        log("iAP invalid bare RST ignored seq="+f.seq+" ack="+f.ack+
            " session="+f.session+" len="+f.payload.size)
    }
    private fun receive(f:IapWire.Frame) {
        log("iAP frame RX "+frameLine(f))
        if(f.flags==0x10){handleBareRst(f);return}
        require(f.flags and 0x08==0){"UNSUPPORTED_LINK_CONTROL: SLP"}
        if(f.flags and 0x20!=0){
            // 24A446 EAK is 0x60 (ACK+EAK), session 0. Its body lists PSNs
            // already received out of order; missing positions are derived from
            // ACK+1..ACK+peerWindow, up to the highest valid listed PSN.
            require(eakSchema==EakSchema.EAK_RECEIVED_LIST_V1){"UNSUPPORTED_LINK_CONTROL: EAK"}
            require(f.flags and 0x60==0x60&&f.session==0&&f.flags and 0x98==0)
            // The firmware EAK action always carries at least one received PSN;
            // an empty 0x60 frame is malformed, not a no-gap acknowledgement.
            require(f.payload.isNotEmpty()){"Malformed EAK without received PSN"}
            val missing=missingFromEak(f.ack,f.payload)
            synchronized(ackLock){
                // EAK carries the same cumulative ACK field as a plain ACK. Apply it
                // before marking selective gaps so already-confirmed slots are released
                // and the sender can immediately refill the peer window.
                acceptCumulativeAck(f.ack)
                missing.forEach{txSlots[it]?.retransmitRequested=true}
                ackLock.notifyAll()
            }
            return
        }
        if(f.flags and 0x04!=0){handleCommand(f);return}
        if(f.flags and 0x40!=0){ synchronized(ackLock){acceptCumulativeAck(f.ack)} }
        if(f.payload.isEmpty())return
        require(f.flags and 0x80==0 && f.flags and 0x20==0) { "Unsupported runtime link control" }
        if(noRetransmit){
            // 无重传模式不生成 ACK；非连续 PSN 走 SendRST/丢弃（ch01 §3.4、iap2-fast-mode24）。
            val gap=(f.seq-receiveSeq) and 255
            if(gap!=1){write(IapWire.Frame(0x10,0,0,0,ByteArray(0)));return}
            deliver(f);return
        }
        val distance=(f.seq-receiveSeq) and 255
        if(distance==0||distance>127){write(IapWire.Frame(0x40,sendSeq,receiveSeq,0,byteArrayOf()));return}
        if(distance>receiveWindow){write(IapWire.Frame(0x40,sendSeq,receiveSeq,0,byteArrayOf()));return}
        if(distance>1){
            if(f.seq !in outOfOrder){require(outOfOrder.size<32);outOfOrder[f.seq]=f}
            if(eakSchema==EakSchema.UNSUPPORTED){
                write(IapWire.Frame(0x40,sendSeq,receiveSeq,0,byteArrayOf()));return
            }
            // EAK body contains the received out-of-order PSNs, in queue order;
            // the peer derives the missing positions from ACK and its window.
            val received=outOfOrder.keys.map{it.toByte()}.toByteArray()
            // Firmware emits one EAK and bounds its body by the complete-frame
            // payload room; it does not emit a train of EAKs for one ACK action.
            write(IapWire.Frame(0x60,sendSeq,receiveSeq,0,
                received.copyOf(minOf(received.size,maxPayloadBytes()))))
            return
        }
        deliver(f)
        while(true){val next=outOfOrder.remove((receiveSeq+1) and 255)?:break;deliver(next)}
        scheduleAckAfterDelivery()
    }
    /** Firmware CMD/bit2 path (0x10000b690 -> 0x1000d4c94).
     *  CMD frames use link session 0 and are not CSM fragments.  The native
     *  handler consumes only 0x54/0x55, mapping them to FSM events 9/10;
     *  unknown opcodes return to the invalid-packet path. */
    private fun handleCommand(f:IapWire.Frame){
        require(f.session==0){"CMD frame must use link session 0"}
        require(f.payload.isNotEmpty()){"CMD frame missing opcode"}
        // CMD2-02: version 1 returns unhandled and does not update RX.  Link
        // version 3 still uses packetVersion=1 framing, hence this separate
        // negotiated version field.
        if(linkVersion==1){
            log("iAP CMD opcode="+(f.payload[0].toInt() and 255).toString(16)+
                " ignored for link version 1")
            return
        }
        receiveSeq=f.seq
        val opcode=f.payload[0].toInt() and 255
        val body=f.payload.copyOfRange(1,f.payload.size)
        val event=when(opcode){0x54->9;0x55->10;else->null}
        if(event==null){
            log("iAP CMD opcode="+opcode.toString(16)+" ignored by firmware CMD path len="+body.size)
            return
        }
        val timingContextRequired=opcode==0x55
        log("iAP CMD time-sync opcode="+opcode.toString(16)+" fsmEvent="+event+
            " timingContextRequired="+timingContextRequired+" len="+body.size)
        require(incoming.offer(IapCommand.Control(opcode,opcode,body,f,event,timingContextRequired))) { "iAP command queue overflow" }
    }
    /** Schedule the receive-side cumulative ACK exactly as the firmware path:
     *  maxAck=0 (or a reached threshold) sends immediately; otherwise the first
     *  ordered delivery starts one ack_ms timer.  The timer is generation-bound
     *  so a Detection/RST restart cannot emit an ACK for the old link. */
    private fun scheduleAckAfterDelivery(){
        var immediate=false
        val epoch=synchronizationEpoch
        synchronized(ackLock){
            val distance=(receiveSeq-sentAck) and 255
            if(distance==0)return
            ackPending=true
            if(maxCumulativeAck<=0||distance>=maxCumulativeAck){
                ackTask?.cancel(false);ackTask=null;immediate=true
            }else if(ackTask==null){
                val delay=ackTimeoutMs.coerceAtLeast(1L)
                ackTask=ackScheduler.schedule({
                    synchronized(ackLock){ackTask=null}
                    sendPendingAck(epoch)
                },delay,TimeUnit.MILLISECONDS)
            }
        }
        if(immediate)sendPendingAck(epoch)
    }
    private fun sendPendingAck(expectedEpoch:Long){
        val frame=synchronized(ackLock){
            if(closed.get()||expectedEpoch!=synchronizationEpoch||!ackPending)return
            IapWire.Frame(0x40,sendSeq,receiveSeq,0,byteArrayOf())
        }
        runCatching{write(frame)}.onFailure{t->
            if(!closed.get()){error=t;close();failure(t)}
        }
        // A receive raced the output write and advanced receiveSeq; the stale
        // ACK was not allowed to clear ackPending, so arm the current epoch.
        synchronized(ackLock){
            if(ackPending&&expectedEpoch==synchronizationEpoch&&!closed.get()){
                ackTask=null
            }else return
        }
        scheduleAckAfterDelivery()
    }
    /** Apply the firmware's cumulative ACK rule to the live TX window. ACKs outside the
     *  current peer window are ignored; an accepted ACK releases every live slot at or before
     *  that PSN, including slots that do not have an exact ACK-sized one-to-one match. */
    private fun acceptCumulativeAck(ack:Int){
        val last=sendSeq
        val ahead=(ack-last) and 255
        // A modulo-256 distance of 128 is ambiguous and is outside the maximum
        // negotiated window (127); treat it as an invalid future ACK.
        if(ahead in 1..128)return
        if(receivedAck>=0){
            val advance=(ack-receivedAck) and 255
            if(advance in 128..255)return
        }
        if(peerWindow>0&&((last-ack) and 255)>peerWindow)return
        receivedAck=ack
        acknowledged=ack
        val done=txSlots.values.filter{((ack-it.seq) and 255)<128}.map{it.seq}
        done.forEach{txSlots.remove(it)}
        pendingSeq=txSlots.keys.firstOrNull()?:-1
        ackLock.notifyAll()
    }
    private fun maxPayloadBytes():Int {
        val checksumBytes=if(packetVersion==2)2 else 1
        return maxPacket-8-2*checksumBytes
    }
    private fun missingFromEak(ack:Int,received:ByteArray):Set<Int>{
        val seen=received.map{it.toInt() and 255}.toSet()
        var highest=0
        for(distance in 1..peerWindow){
            val seq=(ack+distance) and 255
            if(seq in seen)highest=distance
        }
        if(highest==0)return emptySet()
        return (1..highest).asSequence()
            .map{(ack+it) and 255}
            .filter{it !in seen}
            .toSet()
    }
    private fun deliver(f:IapWire.Frame){
        receiveSeq=f.seq
        if(f.session!=control){log("Unsupported iAP session "+f.session);return}
        // A new link payload can finish a maximum-size CSM and already contain the next one.
        // Bound the accumulated byte window, then use each CSM total to retain its tail separately.
        require(partial.size()+f.payload.size<=65535+localMaxRxFrameBytes-10)
        partial.write(f.payload)
        var all=partial.toByteArray(); var at=0
        while(all.size-at>=2) {
            // Firmware CSM framing is a bytewise scanner for the marker. A
            // failed marker drops the current candidate byte and resumes
            // scanning; the local short-length guard follows the same bounded
            // resynchronization policy without claiming a native total<6 rule.
            if(all[at]!=0x40.toByte()||all[at+1]!=0x40.toByte()){at++;continue}
            if(all.size-at<6)break
            val n=IapWire.u16(all,at+2)
            if(n<6){at++;continue}
            if(all.size-at<n)break
            val id=IapWire.u16(all,at+4)
            val body=all.copyOfRange(at+6,at+n)
            // 先分类、再解析：载荷也可能是 iAP1 风格的 lingo 包，TLV 解析器吃不下它 ——
            // 之前正好是在这里抛异常，把整条 iAP 链路一起带下去。
            val lingo=IapMessageRouter.lingoMessage(body)
            val command:IapCommand=if(lingo!=null)IapCommand.Lingo(id,lingo)else IapCommand.Fields(id,IapWire.parseFieldList(body))
            require(incoming.offer(command)) { "iAP command queue overflow" }; at+=n
        }
        require(all.size-at<=65535)
        partial.reset(); if(at<all.size)partial.write(all,at,all.size-at)
    }
    @Synchronized fun send(id:Int, fields:List<Pair<Int,ByteArray>> = emptyList(),expectedGeneration:Int?=null) =
        sendCsm(IapWire.csm(id,fields),expectedGeneration)
    /** 原始 CSM（例如 `1d03` 的字段拒绝条目）；分片/ACK/重传与 [send] 完全相同。 */
    fun sendRaw(csm:ByteArray,expectedGeneration:Int?=null) = sendCsm(csm,expectedGeneration)
    /**
     * Firmware-equivalent fire-and-forget submission. The return value only
     * reports whether the message entered the ordered transmit queue. ACK,
     * retransmission exhaustion, link restart, and generation-gate failures are
     * reported through [completion] on the worker thread.
     */
    fun sendAsync(id:Int, fields:List<Pair<Int,ByteArray>> = emptyList(),
                  expectedGeneration:Int?=null,
                  completion:(Throwable?)->Unit = {}):Boolean =
        sendRawAsync(IapWire.csm(id,fields),expectedGeneration,completion)

    /** Async form for already-framed CSM bytes. */
    fun sendRawAsync(csm:ByteArray,expectedGeneration:Int?=null,
                     completion:(Throwable?)->Unit = {}):Boolean {
        if(closed.get()||error!=null)return false
        val copy=csm.copyOf()
        return try {
            asyncSender.execute {
                var failureCause:Throwable?=null
                try { sendCsm(copy,expectedGeneration) }
                catch(t:Throwable){ failureCause=t }
                finally { runCatching{completion(failureCause)} }
            }
            true
        } catch(_:RejectedExecutionException) { false }
    }

    /**
     * MyLink 20013: 立刻写一帧控制消息，不等它的 ACK，也不走有序 worker。
     *
     * 死锁背景：认证后主循环用 [sendAsync] 把 4e0e 等帧投给单线程 `asyncSender`，
     * 其 worker 进入 @Synchronized 的 [sendCsm] 后在 `ackLock.wait()` 里等 ACK；
     * 此时它一直占着 `this` 监视器和唯一的 worker。车机发 AE00 后要等 AE01 才
     * ACK 4e0e，于是主循环即便 poll 到 AE00，若再用 [sendAsync] 回 AE01 也只会
     * 排在卡死的 worker 后面，直到 4e0e 超时拆链都发不出去。
     *
     * 这里复用 [sendCsm] 相同的锁顺序（writeLock 快照 -> ackLock 分配 PSN 并登记
     * txSlot -> writeLock 写帧），但**不加 @Synchronized**、不进 ACK 等待循环，
     * 因此不与被卡死的 worker 争 `this` 监视器。登记 txSlot 让后续累积 ACK /
     * 重传记账保持一致：车机对 AE01 的累积 ACK 会一并释放 4e0e 的 slot，
     * [sendCsm] 随即被 [acceptCumulativeAck] 唤醒并正常退出。
     */
    fun postNow(id:Int, fields:List<Pair<Int,ByteArray>> = emptyList(),
                expectedGeneration:Int?=null):Boolean {
        if(closed.get()||error!=null)return false
        val snapshot=synchronized(writeLock){
            check(expectedGeneration==null||expectedGeneration==generation){
                "iAP control generation changed before postNow"}
            val session=checkNotNull(negotiatedControlSession){
                "iAP link has no confirmed control session"}
            Pair(session,synchronizationEpoch)
        }
        val (session,epoch)=snapshot
        val data=IapWire.csm(id,fields)
        val chunks=buildList{
            var p=0
            while(p<data.size){
                val end=minOf(data.size,p+maxPayloadBytes())
                add(data.copyOfRange(p,end));p=end
            }
        }
        val pendingWrites=mutableListOf<IapWire.Frame>()
        synchronized(ackLock){
            check(synchronizationEpoch==epoch&&negotiatedControlSession==session){
                "iAP link synchronization changed during postNow"}
            if(receivedAck<0)receivedAck=sendSeq
            for(chunk in chunks){
                sendSeq=(sendSeq+1) and 255
                txSlots[sendSeq]=TxSlot(sendSeq,chunk,
                    attempts=1,sentAtNanos=System.nanoTime())
                pendingWrites+=IapWire.Frame(0x40,sendSeq,receiveSeq,session.id,chunk)
            }
            pendingSeq=txSlots.keys.firstOrNull()?:-1
        }
        pendingWrites.forEach{frame->
            synchronized(writeLock){
                check(synchronizationEpoch==epoch&&negotiatedControlSession==session){
                    "iAP link synchronization changed during postNow"}
                write(frame)
            }
        }
        log("iAP TX "+id.toString(16)+" (postNow)")
        return true
    }
    @Synchronized private fun sendCsm(data:ByteArray,expectedGeneration:Int?=null) {
        val snapshot=synchronized(writeLock){
            check(expectedGeneration==null||expectedGeneration==generation){"iAP control generation changed before send"}
            val session=checkNotNull(negotiatedControlSession){"iAP link has no confirmed control session"}
            Triple(session,synchronizationEpoch,generation)
        }
        val (session,epoch,controlGeneration)=snapshot
        val chunks=buildList{
            var p=0
            while(p<data.size){
                val end=minOf(data.size,p+maxPayloadBytes())
                add(data.copyOfRange(p,end));p=end
            }
        }
        var nextChunk=0
        while(nextChunk<chunks.size||synchronized(ackLock){txSlots.isNotEmpty()}){
            check(!closed.get()); error?.let{throw IOException("iAP reader failed",it)}
            check(synchronizationEpoch==epoch&&negotiatedControlSession==session){"iAP link synchronization changed during send"}
            val pendingWrites=mutableListOf<IapWire.Frame>()
            val now=System.nanoTime()
            synchronized(ackLock){
                if(receivedAck<0)receivedAck=sendSeq
                if(noRetransmit){
                    while(nextChunk<chunks.size){
                        sendSeq=(sendSeq+1) and 255
                        pendingWrites+=IapWire.Frame(0x40,sendSeq,receiveSeq,session.id,chunks[nextChunk++])
                    }
                }else{
                    val capacity=peerWindow.coerceAtLeast(1)
                    while(nextChunk<chunks.size&&txSlots.size<capacity){
                        sendSeq=(sendSeq+1) and 255
                        txSlots[sendSeq]=TxSlot(sendSeq,chunks[nextChunk++])
                    }
                    val retryLimit=retryCount+1
                    for(slot in txSlots.values.toList()){
                        val due=slot.sentAtNanos==0L||slot.retransmitRequested||
                            (now-slot.sentAtNanos)>=retryMs*1_000_000L
                        if(!due)continue
                        if(slot.attempts>=retryLimit){
                            val timeout=java.net.SocketTimeoutException("iAP ACK timeout seq="+slot.seq)
                            error=timeout;negotiatedControlSession=null;close();failure(timeout);throw timeout
                        }
                        slot.attempts++
                        slot.sentAtNanos=now
                        slot.retransmitRequested=false
                        pendingWrites+=IapWire.Frame(0x40,slot.seq,receiveSeq,session.id,slot.payload)
                    }
                    pendingSeq=txSlots.keys.firstOrNull()?:-1
                }
            }
            pendingWrites.forEach{frame->
                check(synchronizationEpoch==epoch&&!closed.get()){ "iAP link synchronization changed during send" }
                synchronized(writeLock){
                    check(synchronizationEpoch==epoch&&generation==controlGeneration&&negotiatedControlSession==session)
                    write(frame)
                }
            }
            if(noRetransmit)break
            if(nextChunk>=chunks.size&&synchronized(ackLock){txSlots.isEmpty()})break
            synchronized(ackLock){
                if(txSlots.isNotEmpty()&&pendingWrites.isEmpty()){
                    val earliest=txSlots.values.map{it.sentAtNanos}.filter{it>0}.minOrNull()
                    val waitNanos=if(earliest==null)retryMs*1_000_000L
                        else (earliest+retryMs*1_000_000L-System.nanoTime()).coerceAtLeast(1_000_000L)
                    ackLock.wait((waitNanos/1_000_000L).coerceAtLeast(1L))
                }
            }
        }
        synchronized(ackLock){pendingSeq=-1}
        log("iAP TX "+IapWire.u16(data,4).toString(16))
    }
    fun await(id:Int,seconds:Long=20):IapFields = synchronized(consumerLock) {
        val cached=synchronized(deferredLock){deferred.firstOrNull{it.id==id&&it.fields!=null}?.also{deferred.remove(it)}}
        if(cached!=null)return checkNotNull(cached.fields)
        val until=System.nanoTime()+seconds*1_000_000_000
        while(!closed.get()) {
            error?.let {throw IOException("iAP failed",it)}
            val remaining=until-System.nanoTime(); if(remaining<=0)throw SocketTimeoutExceptionCompat("iAP message "+id.toString(16))
            val item=incoming.poll(minOf(remaining,500_000_000),TimeUnit.NANOSECONDS)?:continue
            log("iAP RX "+item.id.toString(16))
            val fields=item.fields
            if(fields!=null&&item.id==id)return fields
            if(item.id==0xaa04||item.id==0x1d03||item.id==0x1d05)throw IOException("Accessory rejected "+item.id.toString(16))
            // 不是目标消息（含 lingo 载荷）一律暂存，绝不丢弃。
            synchronized(deferredLock){require(deferred.size<32){"Deferred iAP queue overflow"};deferred.addLast(item)}
        }; throw IOException("iAP closed")
    }
    /** One consumer, after bootstrap await calls finish; never discards deferred commands. */
    fun poll(millis:Long=500):IapCommand? = synchronized(consumerLock){
        require(millis in 0..1000)
        error?.let{throw IOException("iAP reader failed",it)}
        if(closed.get())throw IOException("iAP closed")
        val item=synchronized(deferredLock){if(deferred.isNotEmpty())deferred.removeFirst() else null}
            ?:incoming.poll(millis,TimeUnit.MILLISECONDS)
        item?.also{log("iAP RX "+it.id.toString(16))}
    }
    override fun close(){
        if(!closed.compareAndSet(false,true))return
        synchronized(writeLock){
            cancelPreSynDeadline()
            cancelPendingSynAck()
            negotiatedControlSession=null;negotiatedSynchronizationSchema=null
        }
        frames.close();runCatching{input.close()};runCatching{output.close()}
        synchronized(ackLock){ackTask?.cancel(false);ackTask=null;ackPending=false;txSlots.clear();pendingSeq=-1;ackLock.notifyAll()}
        reader?.interrupt();asyncSender.shutdownNow();ackScheduler.shutdownNow();handshakeDeadline.shutdownNow()
    }
}
private class SocketTimeoutExceptionCompat(s:String):java.net.SocketTimeoutException(s)
