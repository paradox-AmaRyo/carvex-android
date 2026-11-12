package io.github.iamr0s.carvex.carplay.core

import org.junit.Assert.*
import org.junit.Test
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** An accessory that restarts its link sends a fresh SYN; the link has to re-synchronize on the same
 *  socket instead of treating that SYN as an unsupported runtime frame. */
class IapLinkRestartTest {
    @Test(timeout=15000) fun detectionRevokesDependentsBeforeReplacementSynAndClosesSubscriptionRace(){
        val phoneIn=PipedInputStream(8192);val carOut=PipedOutputStream(phoneIn)
        val carIn=PipedInputStream(8192);val phoneOut=PipedOutputStream(carIn)
        val startRestart=CountDownLatch(1);val finishRestart=CountDownLatch(1)
        val revoked=CountDownLatch(1);val completed=CountDownLatch(1)
        val active=AtomicBoolean(true);val invalidations=AtomicInteger()
        val executor=Executors.newSingleThreadExecutor()
        val link=IapLink(phoneIn,phoneOut,{},{})
        try{
            val accessory=executor.submit{
                synchronize(carOut,carIn,11,2)
                check(startRestart.await(5,TimeUnit.SECONDS))
                carOut.write(IapWire.detection);carOut.flush()
                assertArrayEquals(IapWire.detection,IapWire.exact(carIn,6))
                check(finishRestart.await(5,TimeUnit.SECONDS))
                synchronize(carOut,carIn,31,2)
                completed.countDown()
            }
            link.start(allowDirectSyn=true)
            val epoch=link.linkEpoch
            val binding=SecurityBinding(link.generation,"peer",epoch)
            val gate=SessionEventGate(binding){active.get()}
            gate.authenticated(binding);gate.negotiated(binding)
            link.bindEpoch(epoch){active.set(false);invalidations.incrementAndGet();revoked.countDown()}.use{
                startRestart.countDown()
                assertTrue(revoked.await(5,TimeUnit.SECONDS))
                assertEquals(1,link.generation)
                assertNull(link.negotiatedControlSession)
                assertTrue(link.linkEpoch>epoch)
                assertEquals(403,gate.dispatch{fail("stale callback");200 to byteArrayOf()}.first)
                val late=AtomicBoolean(false)
                link.bindEpoch(epoch){late.set(true)}.use{assertTrue(late.get())}
                finishRestart.countDown()
                assertTrue(completed.await(5,TimeUnit.SECONDS))
                assertEquals(1,invalidations.get())
            }
            accessory.get(5,TimeUnit.SECONDS)
        }finally{startRestart.countDown();finishRestart.countDown();link.close();executor.shutdownNow()}
    }
    private fun syn(version:Int)=byteArrayOf(1,5)+IapWire.be16(2048)+IapWire.be16(100)+IapWire.be16(73)+byteArrayOf(1,3,10,0,version.toByte())
    /** Accessory side of one synchronization: send SYN, expect the SYN-ACK, acknowledge it. */
    private fun synchronize(carOut:PipedOutputStream,carIn:PipedInputStream,seq:Int,version:Int=1){
        carOut.write(IapWire.packet(IapWire.Frame(0x80,seq,0,0,syn(version))));carOut.flush()
        val reply=IapWire.read(carIn)
        assertEquals("reply must be a SYN-ACK",0xc0,reply.flags and 0xc0)
        assertEquals("ack must name our SYN",seq,reply.ack)
        assertEquals("reply must echo the advertised Control version",version,reply.payload[12].toInt() and 255)
        carOut.write(IapWire.packet(IapWire.Frame(0x40,seq,reply.seq,0,byteArrayOf())));carOut.flush()
    }
    @Test(timeout=20000) fun freshAccessorySynResynchronizesOnTheSameSocket(){
        val phoneIn=PipedInputStream(8192);val carOut=PipedOutputStream(phoneIn)
        val carIn=PipedInputStream(8192);val phoneOut=PipedOutputStream(carIn)
        val logs=CopyOnWriteArrayList<String>()
        val failures=CopyOnWriteArrayList<Throwable>()
        val executor=Executors.newSingleThreadExecutor()
        val link=IapLink(phoneIn,phoneOut,{logs.add(it)},{failures.add(it)})
        try{
            val accessory=executor.submit{
                carOut.write(IapWire.detection);carOut.flush()
                assertArrayEquals(IapWire.detection,IapWire.exact(carIn,6))
                synchronize(carOut,carIn,254)
                // The accessory restarted the link: a new SYN with a new sequence on the same socket.
                synchronize(carOut,carIn,9)
                // The link must still carry commands after the restart.
                carOut.write(IapWire.packet(IapWire.Frame(0x40,10,0,10,IapWire.csm(0x4301))));carOut.flush()
            }
            link.start()
            val message=link.await(0x4301,10)
            assertTrue("the restarted link must deliver commands",message.isEmpty())
            assertTrue("the restart must be reported, not swallowed",logs.any{it.contains("re-synchronizing")})
            assertEquals(emptyList<Throwable>(),failures)
            accessory.get(10,TimeUnit.SECONDS)
        }finally{link.close();executor.shutdownNow()}
    }
    @Test(timeout=20000) fun requestedRestartResynchronizesWithoutClosing(){
        val phoneIn=PipedInputStream(8192);val carOut=PipedOutputStream(phoneIn)
        val carIn=PipedInputStream(8192);val phoneOut=PipedOutputStream(carIn)
        val logs=CopyOnWriteArrayList<String>()
        val executor=Executors.newSingleThreadExecutor()
        val link=IapLink(phoneIn,phoneOut,{logs.add(it)},{})
        try{
            val accessory=executor.submit{
                carOut.write(IapWire.detection);carOut.flush()
                assertArrayEquals(IapWire.detection,IapWire.exact(carIn,6))
                synchronize(carOut,carIn,254)
                // Answer the restart request issued by the test thread. The fresh SYN continues the
                // accessory's own sequence, so the command that follows it is in order.
                synchronize(carOut,carIn,10)
                carOut.write(IapWire.packet(IapWire.Frame(0x40,11,0,10,IapWire.csm(0x5703))));carOut.flush()
            }
            link.start()
            // Let the reader thread settle into its read loop before flagging a
            // restart; start() returns as soon as the initial handshake completes,
            // but the reader may still be between iterations, and a restart issued
            // too early can be consumed before the loop logs it.
            Thread.sleep(200)
            link.restart()
            assertTrue("a requested restart must re-run the exchange",logs.any{it.contains("restart requested")})
            assertTrue(link.await(0x5703,10).isEmpty())
            accessory.get(10,TimeUnit.SECONDS)
        }finally{link.close();executor.shutdownNow()}
    }
    @Test(timeout=10000) fun synAckEchoesControlVersionTwo(){
        val phoneIn=PipedInputStream(8192);val carOut=PipedOutputStream(phoneIn)
        val carIn=PipedInputStream(8192);val phoneOut=PipedOutputStream(carIn)
        val executor=Executors.newSingleThreadExecutor()
        val link=IapLink(phoneIn,phoneOut,{},{})
        try{
            val accessory=executor.submit{
                carOut.write(IapWire.detection);carOut.flush()
                assertArrayEquals(IapWire.detection,IapWire.exact(carIn,6))
                synchronize(carOut,carIn,41,2)
            }
            link.start()
            accessory.get(5,TimeUnit.SECONDS)
        }finally{link.close();executor.shutdownNow()}
    }
    @Test(timeout=10000) fun directSynIsAcceptedWithoutDetection(){
        val phoneIn=PipedInputStream(8192);val carOut=PipedOutputStream(phoneIn)
        val carIn=PipedInputStream(8192);val phoneOut=PipedOutputStream(carIn)
        val executor=Executors.newSingleThreadExecutor()
        val link=IapLink(phoneIn,phoneOut,{},{})
        try{
            val accessory=executor.submit{synchronize(carOut,carIn,41,2)}
            link.start(allowDirectSyn=true)
            accessory.get(5,TimeUnit.SECONDS)
        }finally{link.close();executor.shutdownNow()}
    }
}
