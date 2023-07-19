import XCTest
import IrohSwift

final class IrohSwiftTests: XCTestCase {
    func testIrohGet() throws {
        
    }

    func testInitIroh() throws {
        // This is a basic integration test to ensure that file writing and
        // reading from swift works as intended
        let iroh = iroh_initialize()

        iroh_free(iroh)

        print("fin!")
    }
}
