package io.github.iamr0s.carvex.carplay.core

/** iAP2 消息分发 —— 让两套协议族共存，而不是二选一。
 *
 * 背景：本项目此前只实现了无线 CarPlay 那一套 message id（`0x1D/0xAA/0x43/0x4E/0x57`），
 * 而手上这批固件文档描述的是 iAP1 风格的 lingo 消息（`0x55` 包）。两者在同一个 iAP2 控制
 * 会话上都可能出现，所以分发必须**逐条**判断 —— 不能"看第一条消息就锁定协议族"：一旦猜错，
 * 后面每条消息都会走错分支，而症状只是"握手超时"，是最难定位的一类失败。
 *
 * 未知消息一律归 [Route.Unknown]，由调用方记录后继续。客户端要兼容的固件版本不止一个，
 * 遇到没见过的 message id 是常态而不是错误。
 */
object IapMessageRouter {
    /** 已知的无线 CarPlay message id：取自现有实现唯一处理过的那一套，加上无线配对的识别项
     *  （[IapWirelessPairing]：本实现不做那条路，但要知道车机在请求它）。 */
    val wirelessIds:Set<Int> = setOf(
        0x1d00,0x1d01,0x1d02,0x1d03,0x1d05,0x1d06,
        0x4300,0x4301,
        0x4e09,0x4e0a,0x4e0c,0x4e0d,0x4e0e,
        0x5702,0x5703,
        0x5000,0x5001,0x5002,
        0xaa00,0xaa01,0xaa02,0xaa03,0xaa04,0xaa05,0xaa06,
        // Power 族（AE）。部分 OEM 车机（实测雪佛兰 MyLink）在识别完成后发 AE00
        // 请求启动外接配件会话，并等 AE01 应答；不认这两个 id 就会被当成未知命令丢掉。
        0xae00,0xae01
    )+IapWirelessPairing.Message.ids

    sealed interface Route {
        /** 无线 CarPlay 协议族；[id] 是 iAP2 控制会话包的 message id。 */
        data class Wireless(val id:Int):Route
        /** 文档描述的 lingo 协议族：载荷本身就是一个自洽的 `0x55` 包。 */
        data class Lingo(val message:IapLingo.Message):Route
        /** 两边都不认识：记录后继续，不阻断链路。 */
        data class Unknown(val id:Int,val payloadBytes:Int):Route
    }

    fun classify(id:Int,payload:ByteArray):Route {
        if(id in wirelessIds)return Route.Wireless(id)
        lingoMessage(payload)?.let{return Route.Lingo(it)}
        return Route.Unknown(id,payload.size)
    }

    /** 判据是"载荷自身能否解析成长度与校验都自洽的 `0x55` 包"，比"首字节等于 `0x55`"强得多：
     *  TLV field list 的首字节是长度高字节，只看首字节会把刚好以 `0x55` 开头的合法 TLV 误判。
     *  解析失败即返回 null —— 分类路径上不允许抛异常。 */
    fun lingoMessage(payload:ByteArray):IapLingo.Message? {
        if(payload.size<4||!IapLingo.isLingo(payload))return null
        return runCatching{IapLingo.parse(payload)}.getOrNull()
    }
}
