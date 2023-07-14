@_exported import Iroh

import Foundation

public enum IrohError: Error {
    case unexpected(UInt32)
}

public func irohGet(cid: String, peer: String, peerAddr:String, outPath:String) throws {
    let status = iroh_get(cid, peer, peerAddr, outPath)
    guard status == errSecSuccess else {
        throw IrohError.unexpected(status)
    }
}

public func irohGetTicket(ticket: String, outPath: String) throws {
    let status = iroh_get_ticket(ticket, outPath)
    guard status == errSecSuccess else {
        throw IrohError.unexpected(status)
    }
}
