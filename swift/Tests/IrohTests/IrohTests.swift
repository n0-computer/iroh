import XCTest
@testable import IrohSwift

final class IrohSwiftTests: XCTestCase {
    func testIrohGet() throws {
        irhoGet("", "/tmp")
    }
}
